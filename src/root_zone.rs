// src/root_zone.rs
//
// Local root zone support with automatic lifecycle management.
//
// The root zone is a data source, not a cache. It has its own
// lifecycle: loaded_at, serial, refresh schedule, failure tracking.
// It is not invalidated by DNS record TTLs.
//
// Lifecycle:
//   startup: try JSON cache → try text file → spawn background download
//   running: periodic refresh task re-downloads and atomically swaps
//
// The atomic swap uses DelegationSource tagging: root-zone entries
// are removed and re-inserted without touching dynamic entries.

use crate::cache::now_secs;
use crate::recursor::{DelegationEntry, DelegationSource, RecursiveResolver};
use hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

pub const DEFAULT_MAX_AGE_DAYS: u64 = 30;
pub const DEFAULT_REFRESH_HOURS: u64 = 168; // weekly
pub const DEFAULT_URL: &str = "https://www.internic.net/domain/root.zone";
const ROOT_ZONE_TTL_CAP_SECS: u64 = 7 * 86400;
const MIN_DOWNLOAD_BYTES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub enum RootZoneState {
    Valid,
    StaleButUsable,
    TooOld,
    Invalid,
    #[default]
    Missing,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RootZoneStatus {
    pub state: RootZoneState,
    pub serial: Option<u32>,
    pub loaded_at: Option<u64>,
    pub source_path: Option<String>,
    pub source_url: Option<String>,
    pub tld_count: usize,
    pub file_age_days: Option<u64>,
    pub last_refresh_attempt: Option<u64>,
    pub last_refresh_success: Option<u64>,
    pub consecutive_failures: u32,
}

pub struct RootZoneDelegation {
    pub servers: Vec<IpAddr>,
    pub ttl: u32,
}

pub struct RootZoneData {
    pub delegations: HashMap<Name, RootZoneDelegation>,
    pub serial: u32,
    pub loaded_at: u64,
    pub source_path: String,
    pub source_url: String,
}

#[derive(Serialize, Deserialize)]
struct RootZoneCacheJson {
    serial: u32,
    loaded_at: u64,
    source_url: String,
    delegations: Vec<RootZoneCacheEntry>,
}

#[derive(Serialize, Deserialize)]
struct RootZoneCacheEntry {
    name: String,
    ttl: u32,
    servers: Vec<String>,
}

struct RootZoneConfig {
    text_path: PathBuf,
    json_path: PathBuf,
    url: String,
    max_age_days: u64,
    refresh_interval: Duration,
}

impl RootZoneConfig {
    fn from_env() -> Option<Self> {
        // Default to files in the process working directory so
        // operators can drop the root zone next to the binary without
        // needing /var/lib/dns permissions. Overridable via env.
        let text_path = std::env::var("ROOT_ZONE_FILE")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("root.zone"));
        let json_path = std::env::var("ROOT_ZONE_CACHE")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| text_path.with_extension("json"));
        let url = std::env::var("ROOT_ZONE_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_URL.to_string());
        let max_age_days = std::env::var("ROOT_ZONE_MAX_AGE_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_AGE_DAYS);
        let refresh_hours = std::env::var("ROOT_ZONE_REFRESH_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_REFRESH_HOURS);

        Some(Self {
            text_path,
            json_path,
            url,
            max_age_days,
            refresh_interval: Duration::from_secs(refresh_hours * 3600),
        })
    }
}

pub struct RootZoneManager {
    config: RootZoneConfig,
    status: RwLock<RootZoneStatus>,
    recursor: Arc<RecursiveResolver>,
}

static MANAGER: OnceLock<Arc<RootZoneManager>> = OnceLock::new();

pub fn manager() -> Option<&'static Arc<RootZoneManager>> {
    MANAGER.get()
}

pub fn current_status() -> RootZoneStatus {
    match manager() {
        Some(m) => m.snapshot(),
        None => RootZoneStatus::default(),
    }
}

impl RootZoneManager {
    /// Start the root zone manager. Never blocks on the network:
    /// returns as soon as local data is loaded (or determines that
    /// no local data exists) and spawns a background download plus a
    /// periodic refresh task.
    pub async fn start(recursor: Arc<RecursiveResolver>) -> Option<Arc<Self>> {
        let config = RootZoneConfig::from_env()?;

        let manager = Arc::new(Self {
            config,
            status: RwLock::new(RootZoneStatus::default()),
            recursor,
        });

        // Fast paths: local JSON cache, then local text file.
        let initial: Option<RootZoneData> = manager
            .try_load_json()
            .ok()
            .or_else(|| manager.try_load_text().ok());

        match initial {
            Some(data) => {
                let age_days = now_secs().saturating_sub(data.loaded_at) / 86400;
                let state = classify_age(age_days, manager.config.max_age_days);
                manager.install_to_cache(&data);
                manager.set_status_loaded(&data, Some(age_days), state);
                tracing::info!(
                    serial = data.serial,
                    tlds = data.delegations.len(),
                    age_days,
                    ?state,
                    path = %data.source_path,
                    "[ROOT-ZONE] Loaded from local cache"
                );
            }
            None => {
                tracing::info!(
                    "[ROOT-ZONE] No local cache; downloading in background"
                );
                let mgr = manager.clone();
                tokio::spawn(async move {
                    match mgr.download_and_refresh().await {
                        Ok(()) => tracing::info!("[ROOT-ZONE] Initial download complete"),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "[ROOT-ZONE] Initial download failed; using network root servers"
                        ),
                    }
                });
            }
        }

        // Register globally so the metrics handler can see it.
        let _ = MANAGER.set(manager.clone());

        // Spawn the periodic refresh loop.
        let mgr = manager.clone();
        tokio::spawn(async move {
            mgr.refresh_loop().await;
        });

        Some(manager)
    }

    async fn refresh_loop(self: Arc<Self>) {
        tracing::info!(
            interval_secs = self.config.refresh_interval.as_secs(),
            "[ROOT-ZONE] Periodic refresh started"
        );

        let mut interval = tokio::time::interval(self.config.refresh_interval);
        interval.tick().await; // discard immediate first tick

        loop {
            interval.tick().await;
            tracing::info!("[ROOT-ZONE] Starting scheduled refresh");
            match self.download_and_refresh().await {
                Ok(()) => {
                    let s = self.snapshot();
                    tracing::info!(
                        serial = ?s.serial,
                        tlds = s.tld_count,
                        "[ROOT-ZONE] Refresh succeeded"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "[ROOT-ZONE] Refresh failed; keeping previous data");
                    let mut s = self.status.write().unwrap();
                    s.last_refresh_attempt = Some(now_secs());
                    s.consecutive_failures = s.consecutive_failures.saturating_add(1);
                }
            }
        }
    }

    async fn download_and_refresh(&self) -> Result<(), String> {
        let content = self.download().await?;
        let data = parse_root_zone(&content, &self.config.url)?;

        // Sanity check: reject suspiciously small zone files.
        if data.delegations.len() < 100 {
            return Err(format!(
                "root zone parsed to only {} delegations; refusing to install",
                data.delegations.len()
            ));
        }

        self.install_to_cache(&data);

        // Persist both raw and parsed.
        if let Err(e) = std::fs::write(&self.config.text_path, &content) {
            tracing::warn!(error = %e, "[ROOT-ZONE] Could not save text file");
        }
        if let Err(e) = self.save_json(&data) {
            tracing::warn!(error = %e, "[ROOT-ZONE] Could not save JSON cache");
        }

        {
            let mut s = self.status.write().unwrap();
            s.state = RootZoneState::Valid;
            s.serial = Some(data.serial);
            s.loaded_at = Some(data.loaded_at);
            s.source_path = Some(data.source_path.clone());
            s.source_url = Some(data.source_url.clone());
            s.tld_count = data.delegations.len();
            s.file_age_days = Some(0);
            s.last_refresh_attempt = Some(now_secs());
            s.last_refresh_success = Some(now_secs());
            s.consecutive_failures = 0;
        }

        Ok(())
    }

    /// Atomically replace root-zone-sourced delegation entries without
    /// touching dynamically-learned ones. Runs in two steps (retain
    /// then insert); during the brief window between them, queries
    /// fall back to root servers — safe, just slower.
    fn install_to_cache(&self, data: &RootZoneData) {
        let cache = self.recursor.delegation_cache();
        let now = now_secs();
        let cap = ROOT_ZONE_TTL_CAP_SECS;

        // Drop all previous root-zone entries.
        cache.retain(|_, v| v.source != DelegationSource::RootZone);

        let mut injected = 0usize;
        for (tld, del) in &data.delegations {
            if del.servers.is_empty() {
                continue;
            }
            let ttl = (del.ttl as u64).min(cap);
            cache.insert(
                tld.to_string().to_lowercase(),
                DelegationEntry {
                    servers: del.servers.clone(),
                    expires_at: now.saturating_add(ttl),
                    source: DelegationSource::RootZone,
                },
            );
            injected += 1;
        }

        tracing::debug!(injected, "[ROOT-ZONE] Installed into delegation cache");
    }

    async fn download(&self) -> Result<String, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("unified-dns-root-zone-updater/1.0")
            .build()
            .map_err(|e| format!("client: {}", e))?;

        let resp = client
            .get(&self.config.url)
            .send()
            .await
            .map_err(|e| format!("request: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        let content = resp.text().await.map_err(|e| format!("read: {}", e))?;

        if content.len() < MIN_DOWNLOAD_BYTES {
            return Err(format!(
                "suspiciously small payload ({} bytes)",
                content.len()
            ));
        }

        Ok(content)
    }

    fn try_load_json(&self) -> Result<RootZoneData, String> {
        let content = std::fs::read_to_string(&self.config.json_path)
            .map_err(|e| format!("read json: {}", e))?;
        let cached: RootZoneCacheJson =
            serde_json::from_str(&content).map_err(|e| format!("parse json: {}", e))?;

        let mut delegations = HashMap::new();
        for entry in cached.delegations {
            let Ok(name) = Name::from_str(&entry.name) else {
                continue;
            };
            let servers: Vec<IpAddr> = entry
                .servers
                .into_iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .collect();
            if servers.is_empty() {
                continue;
            }
            delegations.insert(
                name,
                RootZoneDelegation {
                    servers,
                    ttl: entry.ttl,
                },
            );
        }

        if delegations.len() < 100 {
            return Err(format!(
                "JSON cache has only {} delegations",
                delegations.len()
            ));
        }

        Ok(RootZoneData {
            delegations,
            serial: cached.serial,
            loaded_at: cached.loaded_at,
            source_path: self.config.json_path.to_string_lossy().to_string(),
            source_url: cached.source_url,
        })
    }

    fn try_load_text(&self) -> Result<RootZoneData, String> {
        let content = std::fs::read_to_string(&self.config.text_path)
            .map_err(|e| format!("read text: {}", e))?;
        parse_root_zone(&content, &self.config.url)
    }

    fn save_json(&self, data: &RootZoneData) -> Result<(), String> {
        let cache = RootZoneCacheJson {
            serial: data.serial,
            loaded_at: data.loaded_at,
            source_url: data.source_url.clone(),
            delegations: data
                .delegations
                .iter()
                .map(|(name, del)| RootZoneCacheEntry {
                    name: name.to_string(),
                    ttl: del.ttl,
                    servers: del.servers.iter().map(|ip| ip.to_string()).collect(),
                })
                .collect(),
        };

        let tmp = self.config.json_path.with_extension("tmp");
        let json = serde_json::to_string(&cache).map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(&tmp, json).map_err(|e| format!("write tmp: {}", e))?;
        std::fs::rename(&tmp, &self.config.json_path).map_err(|e| format!("rename: {}", e))?;
        Ok(())
    }

    fn set_status_loaded(&self, data: &RootZoneData, age_days: Option<u64>, state: RootZoneState) {
        let mut s = self.status.write().unwrap();
        s.state = state;
        s.serial = Some(data.serial);
        s.loaded_at = Some(data.loaded_at);
        s.source_path = Some(data.source_path.clone());
        s.source_url = Some(data.source_url.clone());
        s.tld_count = data.delegations.len();
        s.file_age_days = age_days;
    }

    pub fn snapshot(&self) -> RootZoneStatus {
        self.status.read().unwrap().clone()
    }

    /// For tests / admin: force an immediate refresh.
    pub async fn force_refresh(&self) -> Result<(), String> {
        self.download_and_refresh().await
    }
}

fn classify_age(age_days: u64, max_age_days: u64) -> RootZoneState {
    if age_days > max_age_days {
        RootZoneState::TooOld
    } else if age_days > max_age_days / 2 {
        RootZoneState::StaleButUsable
    } else {
        RootZoneState::Valid
    }
}

// ─── Parser ────────────────────────────────────────────────────────────────

pub fn parse_root_zone(content: &str, source_url: &str) -> Result<RootZoneData, String> {
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
                if !seen_soa && fields.len() >= 7 {
                    if let Ok(s) = fields[6].parse::<u32>() {
                        serial = s;
                        seen_soa = true;
                    }
                }
            }
            "NS" => {
                if fields.len() < 5 || owner.is_root() {
                    continue;
                }
                let Ok(ns_name) = Name::from_str(fields[4]) else {
                    continue;
                };
                delegations
                    .entry(owner)
                    .or_insert_with(|| RootZoneDelegation {
                        servers: Vec::new(),
                        ttl,
                    });
                // Attach later via glue map.
                glue.entry(ns_name)
                    .or_default()
                    .extend_from_slice(&[]);
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

    // Rebuild delegation -> server mapping. We need the NS name to look
    // up glue, so redo the parse for NS records.
    let mut ns_owners: HashMap<Name, Vec<Name>> = HashMap::new();
    for line in &lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 || fields[3] != "NS" {
            continue;
        }
        let Ok(owner) = Name::from_str(fields[0]) else {
            continue;
        };
        if owner.is_root() {
            continue;
        }
        let Ok(ns_name) = Name::from_str(fields[4]) else {
            continue;
        };
        ns_owners.entry(owner).or_default().push(ns_name);
    }

    for (owner, ns_names) in ns_owners {
        let Some(del) = delegations.get_mut(&owner) else {
            continue;
        };
        for ns in &ns_names {
            if let Some(ips) = glue.get(ns) {
                del.servers.extend_from_slice(ips);
            }
        }
    }

    delegations.retain(|_, del| !del.servers.is_empty());

    if delegations.is_empty() {
        return Err("no usable TLD delegations parsed".to_string());
    }

    Ok(RootZoneData {
        delegations,
        serial,
        loaded_at: now_secs(),
        source_path: String::new(),
        source_url: source_url.to_string(),
    })
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
