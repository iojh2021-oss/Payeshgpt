use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::cors::{Any, CorsLayer};

const MAX_LIVE_BYTES: usize = 600_000; // one snapshot
const MAX_LIVE_DEVICES: usize = 100;
const WATCH_WINDOW_MS: u64 = 15_000; // a dashboard counts as "watching" if it polled within this window

/// Per-device live state. Every top-level key (traffic, av, sys, ...) carries the seq at which it last changed,
/// so a dashboard only downloads the sections that are newer than what it already has.
struct Live {
    seq: u64,
    at: u64,
    keys: HashMap<String, (u64, serde_json::Value)>,
}

#[derive(Clone)]
struct AppState {
    token: String,
    ingest_token: String,
    devices: Arc<RwLock<HashMap<String, DeviceReport>>>,
    live: Arc<RwLock<HashMap<String, Live>>>,
    watch: Arc<RwLock<HashMap<String, u64>>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct DeviceReport {
    id: String,
    name: String,
    #[serde(default)] model: String,
    #[serde(default)] android: String,
    #[serde(default)] app_version: String,
    #[serde(default)] last_seen: String,
    #[serde(default)] online: bool,
    #[serde(default)] vpn: bool,
    #[serde(default)] guard: bool,
    #[serde(default)] db: String,
    #[serde(default)] score: Option<i64>,
    #[serde(default)] memory: String,
    #[serde(default)] threads: Option<u64>,
    #[serde(default)] tcp: Option<u64>,
    #[serde(default)] udp: Option<u64>,
    #[serde(default)] packages: Option<u64>,
    #[serde(default)] system_apps: Option<u64>,
    #[serde(default)] user_apps: Option<u64>,
    #[serde(default)] files_scanned: Option<u64>,
    #[serde(default)] events: Option<u64>,
    #[serde(default)] alerts: Option<u64>,
    #[serde(default)] hashes: Option<u64>,
    #[serde(default)] certs: Option<u64>,
    #[serde(default)] domains: Option<u64>,
    #[serde(default)] apps: Vec<serde_json::Value>,
    #[serde(default)] scans: Vec<serde_json::Value>,
    #[serde(default)] logs: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct DeviceList {
    devices: Vec<DeviceReport>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

#[derive(Deserialize)]
struct SinceQ {
    since: Option<u64>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

fn authorized(h: &HeaderMap, t: &str) -> bool {
    let e = format!("Bearer {t}");
    h.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| ct_eq(v.as_bytes(), e.as_bytes()))
        .unwrap_or(false)
}

fn err(code: StatusCode, e: &'static str) -> Response {
    (code, Json(ErrorBody { error: e })).into_response()
}

fn valid_id(id: &str) -> bool {
    !id.trim().is_empty() && id.len() <= 160
}

fn watching(s: &AppState, id: &str) -> bool {
    match s.watch.read() {
        Ok(w) => w.get(id).map(|t| now_ms().saturating_sub(*t) < WATCH_WINDOW_MS).unwrap_or(false),
        Err(_) => false,
    }
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"ok": true, "service": "payesh-dashboard-api"}))
}

async fn list(State(s): State<AppState>, h: HeaderMap) -> Response {
    if !authorized(&h, &s.token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let mut v = match s.devices.read() {
        Ok(x) => x.values().cloned().collect::<Vec<_>>(),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "store_unavailable"),
    };
    v.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    (StatusCode::OK, Json(DeviceList { devices: v })).into_response()
}

async fn ingest(State(s): State<AppState>, h: HeaderMap, Json(d): Json<DeviceReport>) -> Response {
    if !(authorized(&h, &s.ingest_token) || authorized(&h, &s.token)) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !valid_id(&d.id) || d.name.trim().is_empty() || d.name.len() > 160 {
        return err(StatusCode::BAD_REQUEST, "invalid_device_identity");
    }
    match s.devices.write() {
        Ok(mut store) => {
            store.insert(d.id.clone(), d);
            (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "store_unavailable"),
    }
}

/// Phone -> server: one or more UI sections (JSON object). Sections are merged by top-level key.
/// The answer tells the phone whether a dashboard is watching.
async fn live_push(
    State(s): State<AppState>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(data): Json<serde_json::Value>,
) -> Response {
    if !(authorized(&h, &s.ingest_token) || authorized(&h, &s.token)) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !valid_id(&id) {
        return err(StatusCode::BAD_REQUEST, "invalid_device_identity");
    }
    let obj = match data {
        serde_json::Value::Object(o) => o,
        _ => return err(StatusCode::BAD_REQUEST, "snapshot_must_be_object"),
    };
    if serde_json::Value::Object(obj.clone()).to_string().len() > MAX_LIVE_BYTES {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "snapshot_too_large");
    }
    match s.live.write() {
        Ok(mut m) => {
            if !m.contains_key(&id) && m.len() >= MAX_LIVE_DEVICES {
                return err(StatusCode::TOO_MANY_REQUESTS, "too_many_devices");
            }
            let dev = m.entry(id.clone()).or_insert_with(|| Live { seq: 0, at: 0, keys: HashMap::new() });
            for (k, v) in obj {
                if k.len() > 40 {
                    continue;
                }
                dev.seq += 1;
                dev.keys.insert(k, (dev.seq, v));
            }
            dev.at = now_ms();
        }
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "store_unavailable"),
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true, "watch": watching(&s, &id)}))).into_response()
}

/// Phone -> server: cheap "is anyone watching?" check while idle.
async fn live_watch(State(s): State<AppState>, Path(id): Path<String>, h: HeaderMap) -> Response {
    if !(authorized(&h, &s.ingest_token) || authorized(&h, &s.token)) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    (StatusCode::OK, Json(serde_json::json!({"watch": watching(&s, &id)}))).into_response()
}

/// Dashboard -> server (admin only): newest snapshot if newer than `since`. Polling counts as "watching".
async fn live_get(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<SinceQ>,
    h: HeaderMap,
) -> Response {
    if !authorized(&h, &s.token) {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !valid_id(&id) {
        return err(StatusCode::BAD_REQUEST, "invalid_device_identity");
    }
    if let Ok(mut w) = s.watch.write() {
        if w.len() < 1000 || w.contains_key(&id) {
            w.insert(id.clone(), now_ms());
        }
    }
    let mut since = q.since.unwrap_or(0);
    match s.live.read() {
        Ok(m) => match m.get(&id) {
            Some(l) => {
                if since > l.seq {
                    since = 0; // server restarted since the dashboard last asked: send everything
                }
                let mut out = serde_json::Map::new();
                for (k, (kseq, v)) in l.keys.iter() {
                    if *kseq > since {
                        out.insert(k.clone(), v.clone());
                    }
                }
                let age = now_ms().saturating_sub(l.at);
                if out.is_empty() {
                    (StatusCode::OK, Json(serde_json::json!({"seq": l.seq, "age_ms": age, "unchanged": true}))).into_response()
                } else {
                    (StatusCode::OK, Json(serde_json::json!({"seq": l.seq, "age_ms": age, "data": out}))).into_response()
                }
            }
            None => (StatusCode::OK, Json(serde_json::json!({"seq": 0, "empty": true}))).into_response(),
        },
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "store_unavailable"),
    }
}

#[tokio::main]
async fn main() {
    let token = env::var("PAYESH_ADMIN_TOKEN").expect("Set PAYESH_ADMIN_TOKEN to a long random secret");
    assert!(token.len() >= 24, "PAYESH_ADMIN_TOKEN must be at least 24 characters");
    let ingest_token = env::var("PAYESH_INGEST_TOKEN").expect("Set PAYESH_INGEST_TOKEN");
    assert!(
        ingest_token.len() >= 24 && ingest_token != token,
        "PAYESH_INGEST_TOKEN must be 24+ chars and differ from admin token"
    );
    let state = AppState {
        token,
        ingest_token,
        devices: Arc::new(RwLock::new(HashMap::new())),
        live: Arc::new(RwLock::new(HashMap::new())),
        watch: Arc::new(RwLock::new(HashMap::new())),
    };
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/devices", get(list))
        .route("/api/v1/telemetry", post(ingest))
        .route("/api/v1/live/{id}", post(live_push).get(live_get))
        .route("/api/v1/live/{id}/watch", get(live_watch))
        .layer(cors)
        .with_state(state);
    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind port 8080");
    println!("Payesh dashboard API listening on {addr}");
    axum::serve(listener, app).await.expect("server error");
}
