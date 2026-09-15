// src/transports/tcp.rs
use crate::engine::limits::{MAX_TCP_MSG_SIZE, MIN_DNS_MSG_SIZE};
use crate::engine::{process_dns_query, AppState, ProcessOutcome};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run_tcp_listener(
    listener: TcpListener,
    state: AppState,
    concurrency_limit: Arc<Semaphore>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                let state_ref = state.clone();

                match concurrency_limit.clone().try_acquire_owned() {
                    Ok(permit) => {
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_length_prefixed_stream(stream, state_ref, "TCP", peer.ip())
                                .await;
                        });
                    }
                    Err(_) => {
                        tracing::warn!(
                            client = %peer.ip(),
                            "[TCP] Concurrency limit reached; dropping connection"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "[TCP] Error accepting connection");
            }
        }
    }
}

pub async fn handle_length_prefixed_stream<S>(
    mut stream: S,
    state: AppState,
    protocol: &'static str,
    client_ip: IpAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut len_buf = [0u8; 2];
    loop {
        let read_len = timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await;
        let req_len = match read_len {
            Ok(Ok(2)) => u16::from_be_bytes(len_buf) as usize,
            _ => break,
        };

        if !(MIN_DNS_MSG_SIZE..=MAX_TCP_MSG_SIZE).contains(&req_len) {
            tracing::debug!(
                protocol,
                client = %client_ip,
                len = req_len,
                "[{}] Invalid TCP frame length; closing stream",
                protocol
            );
            break;
        }

        let mut req_buf = vec![0u8; req_len];
        let read_payload = timeout(IO_TIMEOUT, stream.read_exact(&mut req_buf)).await;
        if !matches!(read_payload, Ok(Ok(_))) {
            break;
        }

        let outcome = process_dns_query(&req_buf, &state, protocol, client_ip).await;

        match outcome {
            ProcessOutcome::Success(resp_wire)
            | ProcessOutcome::ServFail(resp_wire)
            | ProcessOutcome::Truncated(resp_wire) => {
                if resp_wire.len() > MAX_TCP_MSG_SIZE {
                    tracing::error!(
                        protocol,
                        len = resp_wire.len(),
                        "[{}] Response exceeds 64KB TCP frame limit",
                        protocol
                    );
                    break;
                }

                let len_bytes = (resp_wire.len() as u16).to_be_bytes();
                let write_result = timeout(IO_TIMEOUT, async {
                    stream.write_all(&len_bytes).await?;
                    stream.write_all(&resp_wire).await?;
                    stream.flush().await?;
                    Ok::<(), std::io::Error>(())
                })
                .await;

                if !matches!(write_result, Ok(Ok(()))) {
                    break;
                }
            }
            ProcessOutcome::Dropped => {
                continue;
            }
            ProcessOutcome::Malformed => {
                break;
            }
        }
    }
}
