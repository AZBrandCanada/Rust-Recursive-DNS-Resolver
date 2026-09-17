// src/transports/doh3.rs
use super::doh::decode_dns_param;
use crate::engine::limits::MAX_DOH_PAYLOAD;
use crate::engine::{process_dns_query, AppState, ProcessOutcome};
use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use h3_quinn::BidiStream;
use http::{Method, Request, Response, StatusCode};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub async fn run_doh3_listener(
    endpoint: quinn::Endpoint,
    state: AppState,
    concurrency_limit: Arc<Semaphore>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let state_ref = state.clone();
        let sem_ref = concurrency_limit.clone();
        tokio::spawn(async move {
            let Ok(permit) = sem_ref.try_acquire_owned() else {
                tracing::warn!("[DoH3] Concurrency limit reached; rejecting connection");
                return;
            };
            let _permit = permit;
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "[DoH3] QUIC handshake failed");
                    return;
                }
            };

            let h3_conn = match h3::server::builder()
                .build(h3_quinn::Connection::new(conn.clone()))
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "[DoH3] Failed to establish HTTP/3 session");
                    return;
                }
            };

            handle_h3_connection(h3_conn, conn.remote_address().ip(), state_ref).await;
        });
    }
}

async fn handle_h3_connection(
    mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes>,
    client_ip: IpAddr,
    state: AppState,
) {
    while let Ok(Some(resolver)) = h3_conn.accept().await {
        let state_ref = state.clone();
        tokio::spawn(async move {
            let (req, stream) = match resolver.resolve_request().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            handle_h3_request(req, stream, state_ref, client_ip).await;
        });
    }
}

async fn handle_h3_request(
    req: Request<()>,
    mut stream: RequestStream<BidiStream<Bytes>, Bytes>,
    state: AppState,
    client_ip: IpAddr,
) {
    let path = req.uri().path();

    if path == "/health" {
        let payload = serde_json::json!({
            "status": "healthy",
            "cached_records": state.cache.entry_count(),
        });
        if let Ok(resp) = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(())
        {
            let _ = stream.send_response(resp).await;
            let _ = stream.send_data(Bytes::from(payload.to_string())).await;
            let _ = stream.finish().await;
        }
        return;
    }

    if path != "/dns-query" {
        if let Ok(resp) = Response::builder().status(StatusCode::NOT_FOUND).body(()) {
            let _ = stream.send_response(resp).await;
            let _ = stream.finish().await;
        }
        return;
    }

    let raw_query_bytes = match *req.method() {
        Method::GET => {
            let query_str = req.uri().query().unwrap_or_default();
            let dns_param = query_str.split('&').find_map(|pair| {
                let mut it = pair.split('=');
                if it.next()? == "dns" {
                    it.next()
                } else {
                    None
                }
            });

            let Some(encoded) = dns_param else {
                send_error_response(
                    &mut stream,
                    StatusCode::BAD_REQUEST,
                    "Missing dns query parameter",
                )
                .await;
                return;
            };

            match decode_dns_param(encoded) {
                Ok(bytes) if !bytes.is_empty() => bytes,
                _ => {
                    send_error_response(
                        &mut stream,
                        StatusCode::BAD_REQUEST,
                        "Invalid base64url payload",
                    )
                    .await;
                    return;
                }
            }
        }
        Method::POST => {
            let is_dns_message = req
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|ct| ct.starts_with("application/dns-message"))
                .unwrap_or(false);

            if !is_dns_message {
                send_error_response(
                    &mut stream,
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Invalid content-type",
                )
                .await;
                return;
            }

            let mut body = Vec::new();
            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                while chunk.has_remaining() {
                    let slice = chunk.chunk();
                    body.extend_from_slice(slice);
                    let len = slice.len();
                    chunk.advance(len);
                }
                if body.len() > MAX_DOH_PAYLOAD {
                    send_error_response(
                        &mut stream,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Query payload too large",
                    )
                    .await;
                    return;
                }
            }

            if body.is_empty() {
                send_error_response(&mut stream, StatusCode::BAD_REQUEST, "Empty request body")
                    .await;
                return;
            }
            body
        }
        _ => {
            send_error_response(
                &mut stream,
                StatusCode::METHOD_NOT_ALLOWED,
                "Method not allowed",
            )
            .await;
            return;
        }
    };

    let outcome = process_dns_query(&raw_query_bytes, &state, "DoH3", client_ip).await;

    let (status, resp_data) = match outcome {
        ProcessOutcome::Success(wire)
        | ProcessOutcome::ServFail(wire)
        | ProcessOutcome::Truncated(wire) => (StatusCode::OK, wire),
        ProcessOutcome::Malformed => (StatusCode::BAD_REQUEST, b"Malformed DNS message".to_vec()),
        ProcessOutcome::Dropped => (
            StatusCode::TOO_MANY_REQUESTS,
            b"Rate limit exceeded".to_vec(),
        ),
    };

    if let Ok(resp) = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::CACHE_CONTROL, "no-cache")
        .header("access-control-allow-origin", "*")
        .body(())
    {
        let _ = stream.send_response(resp).await;
        let _ = stream.send_data(Bytes::from(resp_data)).await;
        let _ = stream.finish().await;
    }
}

async fn send_error_response(
    stream: &mut RequestStream<BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    msg: &'static str,
) {
    if let Ok(resp) = Response::builder().status(status).body(()) {
        let _ = stream.send_response(resp).await;
        let _ = stream.send_data(Bytes::from_static(msg.as_bytes())).await;
        let _ = stream.finish().await;
    }
}
