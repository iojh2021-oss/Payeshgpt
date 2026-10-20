//! Defensive, read-only evidence correlation for PayeshGPT.
//!
//! This library evaluates observations supplied by trusted collectors. It does not
//! access kernel memory, bypass Android sandboxing, or claim that a clean result
//! proves a device is free of rootkits.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Verified,
    Suspicious,
    Failed,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub category: String,
    pub status: EvidenceStatus,
    /// Short human-readable explanation; do not include secrets or raw user data.
    pub detail: String,
    /// Whether this evidence was verified by a source independent of the device OS.
    #[serde(default)]
    pub independently_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    NoSuspiciousEvidenceObserved,
    Suspicious,
    IntegrityFailure,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub assessment: Assessment,
    pub confidence: &'static str,
    pub evidence_count: usize,
    pub independent_evidence_count: usize,
    pub findings: Vec<String>,
    pub evidence: Vec<Evidence>,
}

/// Correlate evidence conservatively. Missing evidence is never treated as a pass.
pub fn assess(evidence: Vec<Evidence>) -> Report {
    let independent = evidence.iter().filter(|e| e.independently_verified).count();
    let mut findings = Vec::new();
    let failed = evidence.iter().any(|e| e.status == EvidenceStatus::Failed);
    let suspicious = evidence.iter().any(|e| e.status == EvidenceStatus::Suspicious);
    let has_unknown = evidence.iter().any(|e| {
        matches!(e.status, EvidenceStatus::Unavailable | EvidenceStatus::Unknown)
    });
    let has_independent_boot = evidence.iter().any(|e| {
        e.independently_verified
            && e.category == "boot_integrity"
            && e.status == EvidenceStatus::Verified
    });

    if failed {
        findings.push("At least one integrity check reported a failure; investigate the affected component.".into());
    }
    if suspicious {
        findings.push("At least one collector reported suspicious evidence; this is not by itself proof of malware.".into());
    }
    if has_unknown {
        findings.push("Some checks were unavailable or inconclusive; coverage is incomplete.".into());
    }
    if !has_independent_boot {
        findings.push("No independently verified boot-integrity evidence was supplied.".into());
    }
    if evidence.is_empty() {
        findings.push("No evidence was supplied; no security conclusion can be drawn.".into());
    }

    let assessment = if failed {
        Assessment::IntegrityFailure
    } else if suspicious {
        Assessment::Suspicious
    } else if evidence.is_empty() || has_unknown || !has_independent_boot {
        Assessment::Inconclusive
    } else {
        Assessment::NoSuspiciousEvidenceObserved
    };
    let confidence = match assessment {
        Assessment::IntegrityFailure => "elevated concern; validate independently",
        Assessment::Suspicious => "needs investigation",
        Assessment::Inconclusive => "insufficient evidence",
        Assessment::NoSuspiciousEvidenceObserved => "limited to supplied evidence; not a clean bill of health",
    };

    Report {
        schema_version: 1,
        assessment,
        confidence,
        evidence_count: evidence.len(),
        independent_evidence_count: independent,
        findings,
        evidence,
    }
}

/// SHA-256 of bytes explicitly supplied by a caller. This function does not
/// discover or read protected files by itself.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compare an observed SHA-256 against a trusted reference map. The map's
/// provenance must be established by the caller; a local untrusted manifest
/// must not be described as independent validation.
pub fn compare_hashes(observed: &BTreeMap<String, String>, trusted: &BTreeMap<String, String>) -> Vec<Evidence> {
    let mut out = Vec::new();
    for (component, expected) in trusted {
        match observed.get(component) {
            Some(actual) if actual.eq_ignore_ascii_case(expected) => out.push(Evidence {
                id: format!("hash:{component}"),
                category: "file_integrity".into(),
                status: EvidenceStatus::Verified,
                detail: format!("Hash matched the supplied reference for {component}."),
                independently_verified: false,
            }),
            Some(_) => out.push(Evidence {
                id: format!("hash:{component}"),
                category: "file_integrity".into(),
                status: EvidenceStatus::Failed,
                detail: format!("Hash mismatch for {component}; verify reference provenance and device build."),
                independently_verified: false,
            }),
            None => out.push(Evidence {
                id: format!("hash:{component}"),
                category: "file_integrity".into(),
                status: EvidenceStatus::Unavailable,
                detail: format!("No observed hash was supplied for {component}."),
                independently_verified: false,
            }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot(status: EvidenceStatus, independent: bool) -> Evidence {
        Evidence {
            id: "boot-1".into(),
            category: "boot_integrity".into(),
            status,
            detail: "test evidence".into(),
            independently_verified: independent,
        }
    }

    #[test]
    fn missing_evidence_is_inconclusive() {
        assert_eq!(assess(vec![]).assessment, Assessment::Inconclusive);
    }

    #[test]
    fn local_clean_observation_is_not_independent_proof() {
        assert_eq!(assess(vec![boot(EvidenceStatus::Verified, false)]).assessment, Assessment::Inconclusive);
    }

    #[test]
    fn independent_clean_boot_is_limited_positive_result() {
        assert_eq!(assess(vec![boot(EvidenceStatus::Verified, true)]).assessment, Assessment::NoSuspiciousEvidenceObserved);
    }

    #[test]
    fn failed_integrity_has_priority() {
        let r = assess(vec![boot(EvidenceStatus::Failed, true)]);
        assert_eq!(r.assessment, Assessment::IntegrityFailure);
    }

    #[test]
    fn suspicious_evidence_is_flagged() {
        let r = assess(vec![boot(EvidenceStatus::Verified, true), Evidence {
            id: "app-1".into(), category: "app_behavior".into(),
            status: EvidenceStatus::Suspicious, detail: "test".into(),
            independently_verified: false,
        }]);
        assert_eq!(r.assessment, Assessment::Suspicious);
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn missing_component_hash_is_not_clean() {
        let mut trusted = BTreeMap::new();
        trusted.insert("boot".to_string(), "aa".to_string());
        let result = compare_hashes(&BTreeMap::new(), &trusted);
        assert_eq!(result[0].status, EvidenceStatus::Unavailable);
    }
}
