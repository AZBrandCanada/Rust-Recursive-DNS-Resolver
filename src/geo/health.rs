// src/geo/health.rs
//
// Per-node health tracking + async probe loop.
//
// Each enabled node is probed independently on GEO_HEALTH_INTERVAL.
// The probe is a lightweight UDP DNS query to the node's own DNS
// service; this measures the actual service, not just port reachability.
//
// Health check targets are limited to IPs parsed from NODE<N>_IPV4 and
// NODE<N>_IPV6 env vars. No SSRF surface.

use super::config::GeoNode;
use crate::cache::now_secs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HealthState {
    Unknown = 0,
    Healthy = 1,
    Degraded = 2,
    Unhealthy = 3,
}

impl HealthState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Healthy,
            2 => Self::Degraded,
            3 => Self::Unhealthy,
            _ => Self::Unknown,
        }
    }

    /// String form for structured logging and metrics. Retained as
    /// stable API; the current call sites use `{:?}` for brevity.
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unknown => "unknown",
        }
    }
}

pub struct NodeHealth {
    state: AtomicU8,
    consecutive_success: AtomicU32,
    consecutive_failure: AtomicU32,
    last_rtt_us: AtomicU64,
    last_check_at: AtomicU64,
    total_success: AtomicU64,
    total_failure: AtomicU64,
    /// Unix timestamp of the most recent peer heartbeat received from
    /// this node, or 0 if no heartbeat has ever been received (mesh
    /// disabled or the peer has never successfully connected).
    peer_last_heartbeat_at: AtomicU64,
    /// Unix timestamp of when this health entry was created. Used as
    /// the baseline for the startup grace period before a silent peer
    /// is presumed dead.
    registered_at: u64,
    /// Whether the peer last reported itself as healthy. Only valid
    /// when peer_last_heartbeat_at > 0.
    peer_reported_healthy: AtomicU8,
}

impl Default for NodeHealth {
    fn default() -> Self {
        Self {
            state: AtomicU8::new(HealthState::Unknown as u8),
            consecutive_success: AtomicU32::new(0),
            consecutive_failure: AtomicU32::new(0),
            last_rtt_us: AtomicU64::new(0),
            last_check_at: AtomicU64::new(0),
            total_success: AtomicU64::new(0),
            total_failure: AtomicU64::new(0),
            peer_last_heartbeat_at: AtomicU64::new(0),
            peer_reported_healthy: AtomicU8::new(1),
            registered_at: now_secs(),
        }
    }
}

impl NodeHealth {
    pub fn current(&self) -> HealthState {
        HealthState::from_u8(self.state.load(Ordering::Relaxed))
    }

    pub fn rtt_ms(&self) -> Option<f64> {
        let us = self.last_rtt_us.load(Ordering::Relaxed);
        if us == 0 {
            None
        } else {
            Some(us as f64 / 1000.0)
        }
    }

    /// Unix timestamp of the last successful health probe. Retained
    /// for the per-node section of the /metrics endpoint (Phase 2).
    #[allow(dead_code)]
    pub fn last_check_at(&self) -> u64 {
        self.last_check_at.load(Ordering::Relaxed)
    }

    /// Full snapshot of health state for the /metrics endpoint.
    /// Returns (state, total_success, total_failure, last_rtt_ms).
    #[allow(dead_code)]
    pub fn snapshot(&self) -> (HealthState, u64, u64, Option<f64>) {
        (
            self.current(),
            self.total_success.load(Ordering::Relaxed),
            self.total_failure.load(Ordering::Relaxed),
            self.rtt_ms(),
        )
    }

    pub fn record_success(&self, rtt: Duration) {
        self.consecutive_failure.store(0, Ordering::Relaxed);
        let succ = self.consecutive_success.fetch_add(1, Ordering::Relaxed) + 1;
        self.total_success.fetch_add(1, Ordering::Relaxed);
        self.last_rtt_us
            .store(rtt.as_micros() as u64, Ordering::Relaxed);
        self.last_check_at.store(now_secs(), Ordering::Relaxed);

        let current = self.current();
        let new = match current {
            HealthState::Unknown | HealthState::Degraded if succ >= 2 => HealthState::Healthy,
            HealthState::Unhealthy if succ >= 3 => HealthState::Degraded,
            other => other,
        };
        self.state.store(new as u8, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.consecutive_success.store(0, Ordering::Relaxed);
        let fail = self.consecutive_failure.fetch_add(1, Ordering::Relaxed) + 1;
        self.total_failure.fetch_add(1, Ordering::Relaxed);
        self.last_check_at.store(now_secs(), Ordering::Relaxed);

        let current = self.current();
        let new = match current {
            HealthState::Unknown | HealthState::Healthy if fail >= 3 => HealthState::Degraded,
            HealthState::Degraded if fail >= 5 => HealthState::Unhealthy,
            HealthState::Unknown if fail >= 5 => HealthState::Unhealthy,
            other => other,
        };
        self.state.store(new as u8, Ordering::Relaxed);
    }

    /// Apply an authenticated peer heartbeat from this node.
    pub fn apply_peer_heartbeat(&self, reported_healthy: bool, _reported_at: u64) {
        self.peer_last_heartbeat_at
            .store(now_secs(), Ordering::Relaxed);
        self.peer_reported_healthy
            .store(reported_healthy as u8, Ordering::Relaxed);
    }

    /// Whether this node should be excluded from selection based on
    /// peer mesh signal alone.
    ///
    /// Caller must ensure the peer mesh is enabled before using this.
    /// When the mesh is disabled, do not call this (or always treat
    /// the result as `false`).
    ///
    /// Behavior:
    ///   * If a heartbeat has been received and it explicitly said
    ///     `healthy=false`, exclude immediately.
    ///   * If the last heartbeat is older than `3 * interval`,
    ///     exclude (stale).
    ///   * If no heartbeat has ever been received, apply a startup
    ///     grace period of `3 * interval` from the time this entry
    ///     was registered. After the grace period, treat as failed.
    ///     Before it, allow (in case the mesh is just starting up).
    pub fn excluded_by_peer_mesh(&self, now: u64, heartbeat_interval_secs: u64) -> bool {
        let grace = heartbeat_interval_secs.saturating_mul(3);
        let last = self.peer_last_heartbeat_at.load(Ordering::Relaxed);

        if last == 0 {
            // Never heard from this peer. Enforce grace period from
            // registration time so a slow mesh startup doesn't cause
            // all peers to be excluded at t=0.
            return now.saturating_sub(self.registered_at) > grace;
        }

        if now.saturating_sub(last) > grace {
            return true;
        }

        self.peer_reported_healthy.load(Ordering::Relaxed) == 0
    }
}

pub struct HealthRegistry {
    pub nodes: Vec<(String, Arc<NodeHealth>)>,
}

impl HealthRegistry {
    pub fn new(nodes: &[GeoNode]) -> Self {
        let mut list = Vec::new();
        for n in nodes {
            list.push((n.name.clone(), Arc::new(NodeHealth::default())));
        }
        Self { nodes: list }
    }

    pub fn get(&self, name: &str) -> Option<Arc<NodeHealth>> {
        self.nodes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, h)| h.clone())
    }
}

/// Minimal DNS query for `example.com A` in wire format. Used as a
/// health-check probe; any well-formed response counts as success.
const HEALTH_QUERY: &[u8] = &[
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
    b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
];

async fn check_node(node: &GeoNode, rtt_budget: Duration) -> Option<Duration> {
    let addr: SocketAddr = if let Some(v4) = node.ipv4 {
        SocketAddr::new(std::net::IpAddr::V4(v4), 53)
    } else {
        let v6 = node.ipv6?;
        SocketAddr::new(std::net::IpAddr::V6(v6), 53)
    };

    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).await.ok()?;
    socket.connect(addr).await.ok()?;

    let start = std::time::Instant::now();
    socket.send(HEALTH_QUERY).await.ok()?;
    let mut buf = [0u8; 512];
    let _n = timeout(rtt_budget, socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(start.elapsed())
}

pub async fn run_loop(config: super::config::GeoConfig, registry: Arc<HealthRegistry>) {
    if !config.enabled {
        return;
    }

    tracing::info!(
        interval_secs = config.health_interval.as_secs(),
        nodes = config.nodes.len(),
        "[GEO] health check loop started"
    );

    let mut interval = tokio::time::interval(config.health_interval);
    interval.tick().await; // skip immediate

    loop {
        interval.tick().await;

        let mut set = tokio::task::JoinSet::new();
        for node in &config.nodes {
            if !node.enabled {
                continue;
            }
            let node = node.clone();
            let health = registry.get(&node.name).unwrap();
            set.spawn(async move {
                match check_node(&node, Duration::from_secs(3)).await {
                    Some(d) => {
                        tracing::debug!(
                            node = %node.name,
                            rtt_ms = d.as_secs_f64() * 1000.0,
                            "[GEO] health OK"
                        );
                        health.record_success(d);
                    }
                    None => {
                        tracing::debug!(node = %node.name, "[GEO] health FAIL");
                        health.record_failure();
                    }
                }
            });
        }
        while set.join_next().await.is_some() {}
    }
}
