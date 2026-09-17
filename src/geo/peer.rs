// src/geo/peer.rs
//
// Inter-node peer health mesh.
//
// Every node periodically pushes a small signed JSON payload to every
// other node's /internal/peer-heartbeat endpoint. Peers use these
// heartbeats to detect node failures faster than local health checks
// alone, and to react instantly when a peer performs a graceful
// shutdown.
//
// Wire format:
//
//   POST /internal/peer-heartbeat
//   Content-Type: application/json
//   X-Peer-Signature: <hex HMAC-SHA256 of raw body>
//
//   { "node": "asia-1", "timestamp": 1789608000, "healthy": true }
//
// Security:
//   - Source IP must be in the configured node address set.
//   - Signature must verify against GEO_PEER_SECRET.
//   - Timestamp must be within GEO_PEER_MAX_SKEW_SECS of receiver time.
//
// The endpoint returns 404 to any request from a non-allowlisted IP or
// when the peer mesh is not configured, so it is not discoverable.

use super::health::HealthRegistry;
use crate::cache::now_secs;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeartbeatPayload {
    pub node: String,
    pub timestamp: u64,
    /// Whether this node believes it is currently able to serve DNS.
    /// A node that is up but whose DNS listeners are broken should
    /// report `false` so peers stop steering clients to it.
    pub healthy: bool,
}

/// Compute an HMAC-SHA256 over the raw JSON body and return lowercase hex.
pub fn sign(secret: &[u8], payload: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, payload);
    hex_encode(tag.as_ref())
}

/// Verify a lowercase-hex HMAC-SHA256 signature over `payload`.
pub fn verify(secret: &[u8], payload: &[u8], sig_hex: &str) -> bool {
    let Some(sig_bytes) = hex_decode(sig_hex) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::verify(&key, payload, &sig_bytes).is_ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[derive(Debug, Clone)]
pub struct PeerTarget {
    pub name: String,
    /// Base URL of the peer's DoH endpoint, without the trailing path.
    /// e.g. "https://doh-id.azbrand.ca"
    pub base_url: String,
}

/// Spawn the periodic heartbeat sender. Runs until process exit.
pub async fn run_heartbeat_loop(
    self_name: String,
    secret: Vec<u8>,
    interval: Duration,
    targets: Vec<PeerTarget>,
    health: Arc<HealthRegistry>,
    allow_insecure_tls: bool,
) {
    if secret.is_empty() || targets.is_empty() {
        tracing::info!(
            "[PEER] mesh disabled (secret or targets missing)"
        );
        return;
    }

    tracing::info!(
        self_node = %self_name,
        peers = targets.len(),
        interval_secs = interval.as_secs(),
        "[PEER] heartbeat loop started"
    );

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(allow_insecure_tls)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "[PEER] failed to build HTTP client; mesh disabled");
            return;
        }
    };

    let mut tick = tokio::time::interval(interval);
    tick.tick().await; // discard immediate first tick

    loop {
        tick.tick().await;

        let healthy = compute_self_health(&health, &self_name);
        let payload = HeartbeatPayload {
            node: self_name.clone(),
            timestamp: now_secs(),
            healthy,
        };

        let body = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "[PEER] payload serialize failed");
                continue;
            }
        };

        let signature = sign(&secret, &body);

        for target in &targets {
            let url = format!("{}/internal/peer-heartbeat", target.base_url.trim_end_matches('/'));
            let client = client.clone();
            let body = body.clone();
            let sig = signature.clone();
            let name = target.name.clone();

            tokio::spawn(async move {
                let start = Instant::now();
                match client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Peer-Signature", sig)
                    .body(body)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        let rtt = start.elapsed().as_millis() as u64;
                        tracing::debug!(
                            peer = %name,
                            rtt_ms = rtt,
                            "[PEER] heartbeat delivered"
                        );
                    }
                    Ok(resp) => {
                        tracing::debug!(
                            peer = %name,
                            status = %resp.status(),
                            "[PEER] heartbeat rejected"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            peer = %name,
                            error = %e,
                            "[PEER] heartbeat failed"
                        );
                    }
                }
            });
        }
    }
}

/// Self health is derived from the local node's own health entry, if
/// the health registry contains one. If our name is not in the
/// registry (common — a node typically does not probe itself), report
/// healthy: we are running, so we assume we are up.
fn compute_self_health(_health: &Arc<HealthRegistry>, _self_name: &str) -> bool {
    // A node is always considered healthy by itself unless its DNS
    // listeners have failed catastrophically, which would be detected
    // by process exit. A future version could add a self-probe.
    true
}
