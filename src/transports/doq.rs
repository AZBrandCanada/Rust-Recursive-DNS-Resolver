// src/transports/doq.rs
use crate::engine::limits::{MAX_TCP_MSG_SIZE, MIN_DNS_MSG_SIZE};
use crate::engine::{process_dns_query, AppState, ProcessOutcome};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// RFC 9250 error codes
const DOQ_PROTOCOL_ERROR: u32 = 0x2;
const DOQ_EXCESSIVE_LOAD: u32 = 0x4;

pub async fn run_doq_listener(
    endpoint: quinn::Endpoint,
    state: AppState,
    concurrency_limit: Arc<Semaphore>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let state_ref = state.clone();
        let sem_ref = concurrency_limit.clone();
        tokio::spawn(async move {
            let Ok(permit) = sem_ref.try_acquire_owned() else {
                tracing::warn!("[DoQ] Concurrency limit reached; rejecting connection");
                return;
            };
            let _permit = permit;
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "[DoQ] TLS/QUIC handshake failed");
                    return;
                }
            };
            handle_doq_connection(conn, state_ref).await;
        });
    }
}

async fn handle_doq_connection(conn: quinn::Connection, state: AppState) {
    let peer_ip = conn.remote_address().ip();
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let state_ref = state.clone();
        tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            if recv.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let req_len = u16::from_be_bytes(len_buf) as usize;
            if !(MIN_DNS_MSG_SIZE..=MAX_TCP_MSG_SIZE).contains(&req_len) {
                let _ = send.reset(quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR));
                return;
            }

            let mut req_buf = vec![0u8; req_len];
            if recv.read_exact(&mut req_buf).await.is_err() {
                return;
            }

            let outcome = process_dns_query(&req_buf, &state_ref, "DoQ", peer_ip).await;
            match outcome {
                ProcessOutcome::Success(resp_wire)
                | ProcessOutcome::ServFail(resp_wire)
                | ProcessOutcome::Truncated(resp_wire) => {
                    let len_bytes = (resp_wire.len() as u16).to_be_bytes();
                    if send.write_all(&len_bytes).await.is_ok()
                        && send.write_all(&resp_wire).await.is_ok()
                    {
                        let _ = send.finish();
                    }
                }
                ProcessOutcome::Dropped => {
                    let _ = send.reset(quinn::VarInt::from_u32(DOQ_EXCESSIVE_LOAD));
                }
                ProcessOutcome::Malformed => {
                    let _ = send.reset(quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR));
                }
            }
        });
    }
}
