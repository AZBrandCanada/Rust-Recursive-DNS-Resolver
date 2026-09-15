// src/transports/doh.rs
use crate::engine::limits::MAX_DOH_PAYLOAD;
use crate::engine::{process_dns_query, AppState, ProcessOutcome};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use base64::prelude::*;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

#[derive(Deserialize)]
pub struct DohQuery {
    pub dns: Option<String>,
}

pub fn build_doh_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/dns-query",
            get(handle_doh_get)
                .post(handle_doh_post)
                .options(handle_doh_options),
        )
        .route("/health", get(handle_health))
        .layer(DefaultBodyLimit::max(MAX_DOH_PAYLOAD))
        .with_state(state)
}

async fn handle_doh_options() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET, POST, OPTIONS".parse().unwrap(),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        "content-type, accept".parse().unwrap(),
    );
    headers.insert(header::ACCESS_CONTROL_MAX_AGE, "86400".parse().unwrap());
    (StatusCode::OK, headers, ()).into_response()
}

async fn handle_doh_get(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DohQuery>,
) -> Response {
    if !is_acceptable_media_type(&headers) {
        return (
            StatusCode::NOT_ACCEPTABLE,
            "Accept header must include application/dns-message or */*",
        )
            .into_response();
    }

    let encoded = match params.dns {
        None => return (StatusCode::BAD_REQUEST, "Missing 'dns' query parameter").into_response(),
        Some(ref d) if d.trim().is_empty() => {
            return (StatusCode::BAD_REQUEST, "Empty 'dns' query parameter").into_response()
        }
        Some(ref d) => d.trim(),
    };

    let raw_bytes = match decode_dns_param(encoded) {
        Ok(b) if b.is_empty() => {
            return (StatusCode::BAD_REQUEST, "Empty decoded DNS query payload").into_response()
        }
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64url encoding").into_response(),
    };

    if raw_bytes.len() > MAX_DOH_PAYLOAD {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "DNS query exceeds size limit",
        )
            .into_response();
    }

    let client_ip = extract_client_ip(&headers, &peer);
    let outcome = process_dns_query(&raw_bytes, &state, "DoH", client_ip).await;
    handle_dns_outcome(outcome)
}

async fn handle_doh_post(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ct_valid = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.trim()
                .to_ascii_lowercase()
                .starts_with("application/dns-message")
        })
        .unwrap_or(false);

    if !ct_valid {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/dns-message",
        )
            .into_response();
    }

    if !is_acceptable_media_type(&headers) {
        return (
            StatusCode::NOT_ACCEPTABLE,
            "Accept header must include application/dns-message or */*",
        )
            .into_response();
    }

    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty request body").into_response();
    }

    if body.len() > MAX_DOH_PAYLOAD {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "DNS query exceeds size limit",
        )
            .into_response();
    }

    let client_ip = extract_client_ip(&headers, &peer);
    let outcome = process_dns_query(&body, &state, "DoH", client_ip).await;
    handle_dns_outcome(outcome)
}

fn is_acceptable_media_type(headers: &HeaderMap) -> bool {
    if let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) {
        let accept = accept.trim().to_ascii_lowercase();
        accept.contains("application/dns-message")
            || accept.contains("*/*")
            || accept.contains("application/*")
    } else {
        true
    }
}

fn handle_dns_outcome(outcome: ProcessOutcome) -> Response {
    match outcome {
        ProcessOutcome::Success(wire)
        | ProcessOutcome::ServFail(wire)
        | ProcessOutcome::Truncated(wire) => make_dns_response(wire),
        ProcessOutcome::Malformed => {
            (StatusCode::BAD_REQUEST, "Malformed or invalid DNS message").into_response()
        }
        ProcessOutcome::Dropped => {
            (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response()
        }
    }
}

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let payload = serde_json::json!({
        "status": "healthy",
        "cached_records": state.cache.len(),
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        payload.to_string(),
    )
}

fn extract_client_ip(headers: &HeaderMap, peer: &SocketAddr) -> IpAddr {
    if peer.ip().is_loopback() {
        if let Some(cf_ip) = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(ip) = cf_ip.trim().parse::<IpAddr>() {
                return ip;
            }
        }

        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
                return ip;
            }
        }

        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    peer.ip()
}

fn decode_dns_param(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let s = input.trim().replace('-', "+").replace('_', "/");
    let pad_len = (4 - (s.len() % 4)) % 4;
    let padded = format!("{}{}", s, "=".repeat(pad_len));
    BASE64_STANDARD.decode(padded)
}

fn make_dns_response(bytes: Vec<u8>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/dns-message".parse().unwrap(),
    );
    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET, POST, OPTIONS".parse().unwrap(),
    );
    (StatusCode::OK, headers, bytes).into_response()
}
