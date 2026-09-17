// src/geo/router.rs
//
// Node selection.
//
// score = 0.5 * geo + 0.3 * latency + 0.2 * health
//
// geo:     1.0 at 0 km, 0.5 at 5000 km, 0.33 at 10000 km
// latency: 1.0 at 0 ms, 0.5 at 100 ms, 0.2 at 400 ms
// health:  1.0 healthy, 0.5 degraded, 0.7 unknown, 0.0 unhealthy
//
// Unhealthy nodes are excluded entirely. Nodes missing either geo or
// latency data receive the neutral 0.5 sub-score, which makes the
// formula degenerate to geographic-only steering on cold start.
//
// Hysteresis is applied by the caller via `hysteresis_pct`, but the
// selection function itself returns the score so the caller can
// implement keep-or-switch decisions.

use super::config::GeoNode;
use super::geoip::ClientLocation;
use super::health::{HealthRegistry, HealthState, NodeHealth};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct ScoreBreakdown {
    pub node_name: String,
    pub score: f64,
    pub distance_km: Option<f64>,
    pub rtt_ms: Option<f64>,
    pub health: &'static str,
    /// Per-component scores. Retained for Phase 2 tuning tools and for
    /// verbose debug output when diagnosing unexpected steering.
    #[allow(dead_code)]
    pub geo_score: f64,
    #[allow(dead_code)]
    pub latency_score: f64,
    #[allow(dead_code)]
    pub health_score: f64,
}

pub struct GeoRouter {
    nodes: Vec<GeoNode>,
    health: Arc<HealthRegistry>,
    #[allow(dead_code)]
    hysteresis_pct: u8,
    /// Peer heartbeat interval used to compute the mesh staleness
    /// window. Passed in from GeoConfig at construction.
    peer_heartbeat_interval_secs: u64,
    /// Whether the peer mesh is configured and running. When false,
    /// peer-based exclusion is skipped entirely so a standalone
    /// deployment is not penalized by the absence of heartbeats.
    peer_mesh_enabled: bool,
}

impl GeoRouter {
    pub fn new(
        nodes: &[GeoNode],
        health: Arc<HealthRegistry>,
        hysteresis_pct: u8,
        peer_heartbeat_interval_secs: u64,
        peer_mesh_enabled: bool,
    ) -> Self {
        Self {
            nodes: nodes.to_vec(),
            health,
            hysteresis_pct,
            peer_heartbeat_interval_secs,
            peer_mesh_enabled,
        }
    }

    /// Score all eligible nodes and return them sorted best-first.
    ///
    /// A node is excluded when either its local health check has
    /// marked it Unhealthy, or the peer mesh has declared it
    /// unavailable (silent past the staleness window, or explicitly
    /// self-reported unhealthy).
    pub fn score_all(
        &self,
        client: Option<&ClientLocation>,
        need_ipv6: bool,
    ) -> Vec<ScoreBreakdown> {
        let now = crate::cache::now_secs();
        let interval = self.peer_heartbeat_interval_secs;

        let mut scores: Vec<ScoreBreakdown> = self
            .nodes
            .iter()
            .filter(|n| n.enabled)
            .filter(|n| !need_ipv6 || n.ipv6.is_some())
            .filter_map(|n| {
                let h = self.health.get(&n.name)?;
                let state = h.current();
                if state == HealthState::Unhealthy {
                    return None;
                }
                if self.peer_mesh_enabled && h.excluded_by_peer_mesh(now, interval) {
                    return None;
                }
                Some(self.score_node(n, &h, client, state))
            })
            .collect();

        scores.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scores
    }

    /// Return the best node name, or None if no eligible nodes exist.
    /// Convenience wrapper around `score_all` for callers that only
    /// need the winner, not the breakdown. Retained as stable API.
    #[allow(dead_code)]
    pub fn select(&self, client: Option<&ClientLocation>, need_ipv6: bool) -> Option<String> {
        self.score_all(client, need_ipv6)
            .into_iter()
            .next()
            .map(|s| s.node_name)
    }

    fn score_node(
        &self,
        node: &GeoNode,
        health: &NodeHealth,
        client: Option<&ClientLocation>,
        state: HealthState,
    ) -> ScoreBreakdown {
        let (geo_score, distance_km) = match (client, node.lat, node.lon) {
            (Some(c), Some(nlat), Some(nlon)) => match (c.latitude, c.longitude) {
                (Some(clat), Some(clon)) => {
                    let d = haversine_km(clat, clon, nlat, nlon);
                    (1.0 / (1.0 + d / 5000.0), Some(d))
                }
                _ => (0.5, None),
            },
            _ => (0.5, None),
        };

        let (latency_score, rtt_ms) = match health.rtt_ms() {
            Some(ms) if ms > 0.0 => (1.0 / (1.0 + ms / 100.0), Some(ms)),
            _ => (0.5, None),
        };

        let (health_score, health_str) = match state {
            HealthState::Healthy => (1.0, "healthy"),
            HealthState::Degraded => (0.5, "degraded"),
            HealthState::Unknown => (0.7, "unknown"),
            HealthState::Unhealthy => (0.0, "unhealthy"),
        };

        let score = 0.5 * geo_score + 0.3 * latency_score + 0.2 * health_score;

        ScoreBreakdown {
            node_name: node.name.clone(),
            score,
            geo_score,
            latency_score,
            health_score,
            distance_km,
            rtt_ms,
            health: health_str,
        }
    }
}

fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0;
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    R * c
}
