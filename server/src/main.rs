use axum::{extract::State,http::{header,HeaderMap,Method,StatusCode},response::IntoResponse,routing::{get,post},Json,Router};
use serde::{Deserialize,Serialize};
use std::{collections::HashMap,env,net::SocketAddr,sync::{Arc,RwLock}};
use tower_http::cors::{Any,CorsLayer};

#[derive(Clone)] struct AppState { token:String, devices:Arc<RwLock<HashMap<String,DeviceReport>>> }
#[derive(Clone,Serialize,Deserialize)] struct DeviceReport {
 id:String,name:String,
 #[serde(default)] model:String,#[serde(default)] android:String,#[serde(default)] app_version:String,#[serde(default)] last_seen:String,
 #[serde(default)] online:bool,#[serde(default)] vpn:bool,#[serde(default)] guard:bool,#[serde(default)] db:String,
 #[serde(default)] score:Option<i64>,#[serde(default)] memory:String,#[serde(default)] threads:Option<u64>,#[serde(default)] tcp:Option<u64>,#[serde(default)] udp:Option<u64>,
 #[serde(default)] packages:Option<u64>,#[serde(default)] system_apps:Option<u64>,#[serde(default)] user_apps:Option<u64>,#[serde(default)] files_scanned:Option<u64>,#[serde(default)] events:Option<u64>,#[serde(default)] alerts:Option<u64>,#[serde(default)] hashes:Option<u64>,#[serde(default)] certs:Option<u64>,#[serde(default)] domains:Option<u64>,
 #[serde(default)] apps:Vec<serde_json::Value>,#[serde(default)] scans:Vec<serde_json::Value>,#[serde(default)] logs:Vec<serde_json::Value>
}
#[derive(Serialize)] struct DeviceList { devices:Vec<DeviceReport> }
#[derive(Serialize)] struct ErrorBody { error:&'static str }
fn authorized(h:&HeaderMap,t:&str)->bool { let e=format!("Bearer {t}");h.get(header::AUTHORIZATION).and_then(|v|v.to_str().ok()).map(|v|ct_eq(v.as_bytes(),e.as_bytes())).unwrap_or(false) }
fn ct_eq(a:&[u8],b:&[u8])->bool { if a.len()!=b.len(){return false} a.iter().zip(b).fold(0u8,|x,(m,n)|x|(m^n))==0 }
async fn health()->impl IntoResponse { Json(serde_json::json!({"ok":true,"service":"payesh-dashboard-api"})) }
async fn list(State(s):State<AppState>,h:HeaderMap)->axum::response::Response { if !authorized(&h,&s.token){return (StatusCode::UNAUTHORIZED,Json(ErrorBody{error:"unauthorized"})).into_response()} let mut v=match s.devices.read(){Ok(x)=>x.values().cloned().collect::<Vec<_>>(),Err(_)=>return (StatusCode::INTERNAL_SERVER_ERROR,Json(ErrorBody{error:"store_unavailable"})).into_response()};v.sort_by(|a,b|a.name.to_lowercase().cmp(&b.name.to_lowercase()));(StatusCode::OK,Json(DeviceList{devices:v})).into_response() }
async fn ingest(State(s):State<AppState>,h:HeaderMap,Json(d):Json<DeviceReport>)->axum::response::Response { if !authorized(&h,&s.token){return (StatusCode::UNAUTHORIZED,Json(ErrorBody{error:"unauthorized"})).into_response()} if d.id.trim().is_empty()||d.name.trim().is_empty()||d.id.len()>160||d.name.len()>160{return (StatusCode::BAD_REQUEST,Json(ErrorBody{error:"invalid_device_identity"})).into_response()} match s.devices.write(){Ok(mut store)=>{store.insert(d.id.clone(),d);(StatusCode::OK,Json(serde_json::json!({"ok":true}))).into_response()},Err(_)=>(StatusCode::INTERNAL_SERVER_ERROR,Json(ErrorBody{error:"store_unavailable"})).into_response()} }
#[tokio::main] async fn main(){let token=env::var("PAYESH_ADMIN_TOKEN").expect("Set PAYESH_ADMIN_TOKEN to a long random secret");assert!(token.len()>=24,"PAYESH_ADMIN_TOKEN must be at least 24 characters");let state=AppState{token,devices:Arc::new(RwLock::new(HashMap::new()))};let cors=CorsLayer::new().allow_origin(Any).allow_methods([Method::GET,Method::POST,Method::OPTIONS]).allow_headers([header::AUTHORIZATION,header::CONTENT_TYPE]);let app=Router::new().route("/health",get(health)).route("/api/v1/devices",get(list)).route("/api/v1/telemetry",post(ingest)).layer(cors).with_state(state);let addr:SocketAddr="0.0.0.0:8080".parse().unwrap();let listener=tokio::net::TcpListener::bind(addr).await.expect("bind port 8080");println!("Payesh dashboard API listening on {addr}");axum::serve(listener,app).await.expect("server error");}
