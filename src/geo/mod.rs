// src/geo/mod.rs
//
// Geo-aware authoritative GSLB layer.
//
// Serves a small set of configured names (e.g. dns.azbrand.ca) with
// the IP address of the "best" node for the requesting client. The
// decision is computed per-request from GeoIP + health + latency data
// and never enters the recursive answer cache.
//
// Inter-node peer telemetry is a Phase 1.5 addition and lives in
// src/geo/mesh.rs, not here.

pub mod authoritative;
pub mod config;
pub mod geoip;
pub mod health;
pub mod router;

pub use config::{GeoConfig, GeoNode};
pub use geoip::{ClientLocation, GeoIpReader};
pub use health::{HealthRegistry, HealthState, NodeHealth};
pub use router::GeoRouter;

use hickory_proto::rr::Name;
use std::sync::Arc;

pub struct GeoState {
    pub config: GeoConfig,
    pub geoip: Option<GeoIpReader>,
    pub health: Arc<HealthRegistry>,
    pub router: GeoRouter,
    pub authoritative_names: Vec<Name>,
}

impl GeoState {
    pub fn new(config: GeoConfig) -> Arc<Self> {
        let geoip = config.geoip_database.as_ref().and_then(|p| {
            match GeoIpReader::open(p) {
                Ok(r) => {
                    tracing::info!(path = %p.display(), "[GEO] GeoIP database loaded");
                    Some(r)
                }
                Err(e) => {
                    tracing::warn!(
                        path = %p.display(),
                        error = %e,
                        "[GEO] GeoIP database failed to load; clients without location will use the default node"
                    );
                    None
                }
            }
        });

        let health = Arc::new(HealthRegistry::new(&config.nodes));
        let router = GeoRouter::new(&config.nodes, health.clone(), config.hysteresis_pct);
        let authoritative_names = config.authoritative_names.clone();

        tracing::info!(
            enabled = config.enabled,
            nodes = config.nodes.len(),
            authoritative_names = authoritative_names.len(),
            geoip_loaded = geoip.is_some(),
            default_node = ?config.default_node,
            routing_ttl = config.routing_ttl,
            "[GEO] GeoState initialized"
        );

        Arc::new(Self {
            config,
            geoip,
            health,
            router,
            authoritative_names,
        })
    }

    pub fn is_authoritative_for(&self, qname: &Name) -> bool {
        self.authoritative_names.iter().any(|n| n == qname)
    }
}
