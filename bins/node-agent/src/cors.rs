//! Permissive CORS for the localhost data plane, so a browser chat client
//! (served from the coordinator/console origin) can upload and download
//! ciphertext directly. CORS only relaxes the browser's cross-origin check —
//! every data-plane call still requires a valid capability token, so this does
//! not widen authorization.

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

pub async fn permissive(req: Request<Body>, next: Next) -> Response {
    let mut resp = if req.method() == Method::OPTIONS {
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .expect("static preflight response")
    } else {
        next.run(req).await
    };
    let h = resp.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET,POST,PUT,OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type,authorization"),
    );
    resp
}
