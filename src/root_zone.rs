// src/root_zone.rs
//
// Optional local root zone support.
//
// Loads an IANA-format root zone file (e.g. from
// https://www.internic.net/domain/root.zone) and extracts TLD
// delegations. Pre-populates the recursor's delegation cache so that
// queries for com/net/org/etc. start at the TLD authoritative servers
// instead of the root servers.
//
// This is a data source, not a cache. It has its own lifecycle
// (loaded_at, serial, file mtime) and is not invalidated by DNS
// record TTLs. If the file is missing, stale, or invalid, the
// recursor falls back to the hardcoded ROOT_SERVERS list without any
// behavioral change.
//
// Root zone delegation entries live in the SAME delegation cache as
// dynamically-learned entries. If a query against a root-zone-sourced
// TLD fails, the existing purge-and-retry-from-root logic kicks in
// and the resolver recovers by querying the network root servers.

use crate::cache::now_secs;
use hickory_proto::rr::Name;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::UNIX_EPOCH;

pub const DEFAULT_MAX_AGE_DAYS: u64 = 30;
/// TLD delegations from a root zone file are typically TTL 172800
/// (48h). We cap at 7 days so an outdated file does not pin us to
/// stale server addresses indefinitely.
const ROOT_ZONE_TTL_CAP_SECS: u64 = 7 * 86400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RootZoneState {
    Valid,
    StaleButUsable,
    TooOld,
    Invalid,
    #[default]
    Missing,
}

#[derive(Debug, Clone, Default)]
pub struct RootZoneStatus {
    pub state: RootZoneState,
    pub serial: Option<u32>,
    pub loaded_at: Option<u64>,
    pub source_path: Option<String>,
    pub tld_count: usize,
    pub file_age_days: Option<u64>,
}

pub struct RootZoneDelegation {
    pub ns_names: Vec<Name>,
    pub servers: Vec<IpAddr>,
    pub ttl: u32,
}

pub struct RootZoneData {
    pub delegations: HashMap<Name, RootZoneDelegation>,
    pub serial: u32,
    pub loaded_at: u64,
    pub source_path: String,
}

static STATUS: OnceLock<RootZoneStatus> = OnceLock::new();

pub fn current_status() -> &'static RootZoneStatus {
    STATUS.get_or_init(RootZoneStatus::default)
}

pub fn install(status: RootZoneStatus) {
    let _ = STATUS.set(status);
}

pub fn load_root_zone(path: &str) -> Result<RootZoneData, String> {
    let path_ref = Path::new(path);
    if !path_ref.exists() {
        return Err(format!("file not found: {}", path));
    }

    let content = std::fs::read_to_string(path_ref)
        .map_err(|e| format!("read failed: {}", e))?;

    let (delegations, serial) = parse_root_zone(&content)?;

    Ok(RootZoneData {
        delegations,
        serial,
        loaded_at: now_secs(),
        source_path: path.to_string(),
    })
}

pub fn file_mtime_secs(path: &str) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn evaluate_state(loaded_at: u64, max_age_days: u64) -> RootZoneState {
    let age_days = now_secs().saturating_sub(loaded_at) / 86400;
    if age_days > max_age_days {
        RootZoneState::TooOld
    } else if age_days > max_age_days / 2 {
        RootZoneState::StaleButUsable
    } else {
        RootZoneState::Valid
    }
}

pub fn ttl_cap() -> u64 {
    ROOT_ZONE_TTL_CAP_SECS
}

// ─── Parser ────────────────────────────────────────────────────────────────

fn parse_root_zone(content: &str) -> Result<(HashMap<Name, RootZoneDelegation>, u32), String> {
    let lines = logical_lines(content);

    let mut delegations: HashMap<Name, RootZoneDelegation> = HashMap::new();
    let mut glue: HashMap<Name, Vec<IpAddr>> = HashMap::new();
    let mut serial = 0u32;
    let mut seen_soa = false;

    for line in &lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let owner_str = fields[0];
        let ttl: u32 = fields[1].parse().unwrap_or(0);
        let rtype = fields[3];

        let Ok(owner) = Name::from_str(owner_str) else {
            continue;
        };

        match rtype {
            "SOA" => {
                // owner TTL IN SOA mname rname serial refresh retry ...
                if !seen_soa && fields.len() >= 7 {
                    if let Ok(s) = fields[6].parse::<u32>() {
                        serial = s;
                        seen_soa = true;
                    }
                }
            }
            "NS" => {
                if fields.len() < 5 {
                    continue;
                }
                // Skip the root's own NS records (they point at the
                // root servers, which we already have hardcoded).
                if owner.is_root() {
                    continue;
                }
                let Ok(ns_name) = Name::from_str(fields[4]) else {
                    continue;
                };
                delegations
                    .entry(owner)
                    .or_insert_with(|| RootZoneDelegation {
                        ns_names: Vec::new(),
                        servers: Vec::new(),
                        ttl,
                    })
                    .ns_names
                    .push(ns_name);
            }
            "A" | "AAAA" => {
                if fields.len() < 5 {
                    continue;
                }
                if let Ok(ip) = fields[4].parse::<IpAddr>() {
                    glue.entry(owner).or_default().push(ip);
                }
            }
            _ => {}
        }
    }

    // Attach glue addresses to each delegation.
    for (_, del) in delegations.iter_mut() {
        for ns in &del.ns_names {
            if let Some(ips) = glue.get(ns) {
                del.servers.extend_from_slice(ips);
            }
        }
    }

    // Drop delegations with no usable server addresses — they cannot
    // be used for iterative resolution anyway.
    delegations.retain(|_, del| !del.servers.is_empty());

    if delegations.is_empty() {
        return Err("no usable TLD delegations parsed".to_string());
    }

    Ok((delegations, serial))
}

/// Strip comments, join continuation lines that use parentheses.
fn logical_lines(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;

    for raw in content.lines() {
        let no_comment = match raw.find(';') {
            Some(idx) => &raw[..idx],
            None => raw,
        };
        let trimmed = no_comment.trim();
        if trimmed.is_empty() && depth == 0 {
            continue;
        }

        for c in trimmed.chars() {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
            }
        }
        if depth < 0 {
            depth = 0;
        }

        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(trimmed);

        if depth == 0 {
            out.push(current.trim().to_string());
            current.clear();
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}
