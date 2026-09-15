// src/transports/udp.rs
use crate::engine::limits::{MAX_UDP_QUERY_SIZE, MAX_UDP_USER_BUF, MIN_DNS_MSG_SIZE};
use crate::engine::{process_dns_query, AppState, ProcessOutcome};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

pub async fn run_udp_listener(
    socket: Arc<UdpSocket>,
    state: AppState,
    concurrency_limit: Arc<Semaphore>,
) {
    let mut buf = vec![0u8; MAX_UDP_USER_BUF];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                if len < MIN_DNS_MSG_SIZE {
                    continue;
                }

                if len > MAX_UDP_QUERY_SIZE {
                    tracing::debug!(
                        len,
                        client = %peer.ip(),
                        "[UDP] Query exceeds resolver-enforced maximum UDP query size (4096 bytes); dropping"
                    );
                    continue;
                }

                let req_wire = buf[..len].to_vec();
                let socket_ref = socket.clone();
                let state_ref = state.clone();

                if let Ok(permit) = concurrency_limit.clone().try_acquire_owned() {
                    tokio::spawn(async move {
                        let _permit = permit;
                        let outcome =
                            process_dns_query(&req_wire, &state_ref, "UDP", peer.ip()).await;

                        match outcome {
                            ProcessOutcome::Success(resp)
                            | ProcessOutcome::ServFail(resp)
                            | ProcessOutcome::Truncated(resp) => {
                                let _ = socket_ref.send_to(&resp, peer).await;
                            }
                            ProcessOutcome::Dropped | ProcessOutcome::Malformed => {}
                        }
                    });
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "[UDP] Error receiving packet");
            }
        }
    }
}
