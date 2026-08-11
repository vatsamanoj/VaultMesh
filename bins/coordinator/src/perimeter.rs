//! Active-perimeter middleware: block known-bad fingerprints at the earliest
//! layer, and record a tamper-evident footprint for every rejected request.
//!
//! In production the fingerprint is a JA3/JA4 + cert-serial + ASN signature
//! derived at the TLS terminator and forwarded as a header. Here it is taken
//! from `x-vault-fingerprint` (falling back to "anonymous").

use crate::state::AppState;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use vault_ports::{IntrusionRecord, IntrusionSink, ThreatResponder};
use vault_proto::WireError;

fn fingerprint(req: &Request) -> String {
    req.headers()
        .get("x-vault-fingerprint")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous")
        .to_string()
}

fn classify(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "bad_or_forged_credential",
        StatusCode::FORBIDDEN => "authorization_violation",
        StatusCode::TOO_MANY_REQUESTS => "abuse_or_dos",
        _ => "suspicious",
    }
}

pub async fn guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let fp = fingerprint(&req);
    let path = req.uri().path().to_string();
    let now = st.clock.now().as_millis();

    // Blocked fingerprints never reach app logic (drop at the earliest layer).
    if st.responder.is_blocked(&fp) {
        let _ = st
            .intrusions
            .record(IntrusionRecord {
                source_ip: fp.clone(),
                ja3: Some(fp.clone()),
                attack_class: "blocked_fingerprint".into(),
                rejection_reason: format!("blocklisted; path={path}"),
                at_millis: now,
            })
            .await;
        return (
            StatusCode::FORBIDDEN,
            Json(WireError::new("blocked", "fingerprint is blocked")),
        )
            .into_response();
    }

    let resp = next.run(req).await;
    let status = resp.status();

    // Any auth/authz/quota rejection is a footprint + a strike.
    if matches!(
        status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
    ) {
        let class = classify(status);
        let decision = st.responder.assess(&fp, class);
        let _ = st
            .intrusions
            .record(IntrusionRecord {
                source_ip: fp.clone(),
                ja3: Some(fp),
                attack_class: class.into(),
                rejection_reason: format!(
                    "status={} path={path} decision={decision:?}",
                    status.as_u16()
                ),
                at_millis: now,
            })
            .await;
    }
    resp
}
