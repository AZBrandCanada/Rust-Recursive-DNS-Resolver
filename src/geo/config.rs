// src/geo/config.rs
//
// Dynamic node configuration. Node slots are discovered by walking
// NODE1_*, NODE2_*, NODE3_*, ... until an empty NODE<N>_NAME is hit.
// There is no hardcoded upper bound; NODE1000 works the same as NODE1.

use hickory_proto::rr::Name;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GeoNode {
    pub name: String,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub enabled: bool,
    /// Human-readable region tag. Retained for Phase 1.5 mesh logging
    /// and for `GEO_DEFAULT_NODE` matching by region, not by name.
    #[allow(dead_code)]
    pub location: Option<String>,
    /// Optional DoH endpoint used by the Phase 1.5 mesh for health
    /// probes over HTTPS rather than raw UDP DNS.
    #[allow(dead_code)]
    pub doh_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GeoConfig {
    pub enabled: bool,
    pub authoritative_names: Vec<Name>,
    pub nodes: Vec<GeoNode>,
    pub geoip_database: Option<PathBuf>,
    pub routing_ttl: u32,
    pub health_interval: Duration,
    pub default_node: Option<String>,
    pub hysteresis_pct: u8,
    /// Maximum number of A/AAAA records to return per GSLB response.
    /// 1 = strict single-IP steering (no failover at DNS layer).
    /// 2+ = multi-IP response ordered best-first, enabling TCP-layer
    /// failover at the cost of clients that shuffle records getting
    /// best-effort steering instead of strict steering.
    /// Clamped to [1, 16].
    pub response_ip_count: u8,
}

impl GeoConfig {
    pub fn from_env() -> Self {
        let enabled = env_bool("GEO_ROUTING_ENABLED", false);

        let authoritative_names = env_str("GEO_AUTHORITATIVE_NAMES", "")
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| {
                let fqdn = if s.ends_with('.') {
                    s.to_string()
                } else {
                    format!("{}.", s)
                };
                match Name::from_str(&fqdn) {
                    Ok(n) => Some(n),
                    Err(e) => {
                        tracing::warn!(name = %s, error = %e, "[GEO] invalid authoritative name; skipping");
                        None
                    }
                }
            })
            .collect();

        let nodes = parse_nodes();

        let geoip_database = env_str("GEOIP_DATABASE", "");
        let geoip_database = if geoip_database.is_empty() {
            None
        } else {
            Some(PathBuf::from(geoip_database))
        };

        let routing_ttl = env_u32("GEO_ROUTING_TTL", 30);
        let health_interval = Duration::from_secs(env_u64("GEO_HEALTH_INTERVAL", 30));

        let default_node = env_str("GEO_DEFAULT_NODE", "");
        let default_node = if default_node.is_empty() {
            None
        } else {
            Some(default_node)
        };

        let hysteresis_pct = env_u8("GEO_HYSTERESIS_PCT", 15).min(50);
        let response_ip_count = env_u8("GEO_IP_FAILOVER_IP", 1).clamp(1, 16);

        Self {
            enabled,
            authoritative_names,
            nodes,
            geoip_database,
            routing_ttl,
            health_interval,
            default_node,
            hysteresis_pct,
            response_ip_count,
        }
    }

    pub fn find_node(&self, name: &str) -> Option<&GeoNode> {
        self.nodes.iter().find(|n| n.name == name)
    }
}

fn parse_nodes() -> Vec<GeoNode> {
    let mut nodes = Vec::new();
    let mut i = 1u32;
    loop {
        let name_var = format!("NODE{}_NAME", i);
        let name = match std::env::var(&name_var) {
            Ok(v) if !v.is_empty() => v,
            _ => break,
        };
        let prefix = format!("NODE{}_", i);

        let ipv4 = std::env::var(format!("{}IPV4", prefix))
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(|s| match s.parse::<Ipv4Addr>() {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!(node = %name, value = %s, error = %e, "[GEO] invalid IPv4; ignoring");
                    None
                }
            });

        let ipv6 = std::env::var(format!("{}IPV6", prefix))
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(|s| match s.parse::<Ipv6Addr>() {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!(node = %name, value = %s, error = %e, "[GEO] invalid IPv6; ignoring");
                    None
                }
            });

        if ipv4.is_none() && ipv6.is_none() {
            tracing::warn!(node = %name, "[GEO] node has no IPv4 or IPv6 address; skipping");
            i += 1;
            continue;
        }

        let location = std::env::var(format!("{}LOCATION", prefix))
            .ok()
            .filter(|s| !s.is_empty());

        let lat = std::env::var(format!("{}LAT", prefix))
            .ok()
            .and_then(|s| s.parse::<f64>().ok());
        let lon = std::env::var(format!("{}LON", prefix))
            .ok()
            .and_then(|s| s.parse::<f64>().ok());

        let enabled = env_bool(&format!("{}ENABLED", prefix), true);

        let doh_url = std::env::var(format!("{}DOH_URL", prefix))
            .ok()
            .filter(|s| !s.is_empty());

        nodes.push(GeoNode {
            name,
            ipv4,
            ipv6,
            location,
            lat,
            lon,
            enabled,
            doh_url,
        });

        i += 1;
    }

    if !nodes.is_empty() {
        tracing::info!(count = nodes.len(), "[GEO] parsed node configuration");
    }

    nodes
}

fn env_bool(k: &str, default: bool) -> bool {
    std::env::var(k)
        .ok()
        .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off" | ""))
        .unwrap_or(default)
}

fn env_str(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}

fn env_u32(k: &str, default: u32) -> u32 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(k: &str, default: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u8(k: &str, default: u8) -> u8 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
