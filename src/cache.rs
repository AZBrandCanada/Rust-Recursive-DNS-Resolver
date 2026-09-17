// src/cache.rs
//
// DNS-aware answer cache.
//
// Uses moka's W-TinyLFU admission to bound memory under DNS traffic
// skew (a small number of names account for most queries). Reads are
// lock-free and sharded; unrelated keys do not contend.
//
// TTL semantics are unchanged from the previous implementation:
// freshness is derived from the authoritative TTL, reads never reset
// the TTL, and the RFC 8767 stale policy is preserved.

use crate::cache_config::cache_config;
use crate::dnssec::DnssecStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MAX_STALE_SECS: u64 = 300;

/// RFC 8767 §4: Recommended small positive TTL (in seconds) when
/// serving stale responses.
pub const STALE_SERVE_TTL: u32 = 30;

pub fn max_stale_secs() -> u64 {
    static MAX_STALE: OnceLock<u64> = OnceLock::new();
    *MAX_STALE.get_or_init(|| {
        std::env::var("MAX_STALE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_STALE_SECS)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheFreshness {
    Fresh,
    Stale,
    Expired,
}

/// Distinguishes positive answers from authenticated denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EntryKind {
    #[default]
    Positive,
    Negative,
}

mod base64_bytes {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64_STANDARD
            .decode(s.trim())
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    #[serde(with = "base64_bytes")]
    pub raw_wire: Vec<u8>,
    pub min_ttl: u32,
    pub cached_at: u64,
    pub last_revalidated_at: u64,
    /// Authoritative DNSSEC validation status. Mandatory field; legacy
    /// entries missing this field are discarded on startup to prevent
    /// insecure downgrades.
    pub dnssec_status: DnssecStatus,
    /// Positive vs negative. Defaulted for backwards compatibility with
    /// existing on-disk cache.json files.
    #[serde(default)]
    pub kind: EntryKind,
}

impl CacheEntry {
    pub fn freshness(&self, now: u64) -> CacheFreshness {
        self.freshness_at(now, max_stale_secs())
    }

    pub fn freshness_at(&self, now: u64, max_stale: u64) -> CacheFreshness {
        let age = now.saturating_sub(self.cached_at);
        let ttl = self.min_ttl as u64;

        if age < ttl {
            CacheFreshness::Fresh
        } else if age < ttl.saturating_add(max_stale) {
            CacheFreshness::Stale
        } else {
            CacheFreshness::Expired
        }
    }
}

/// moka::sync::Cache is internally Arc-based and Clone. We do not wrap
/// it in an outer Arc.
pub type DnsCache = moka::sync::Cache<String, CacheEntry>;

pub fn create_cache() -> DnsCache {
    let cfg = cache_config();
    moka::sync::Cache::builder()
        .max_capacity(cfg.max_answer_entries)
        .build()
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn load_cache_from_disk<P: AsRef<Path>>(cache: &DnsCache, path: P) {
    let path = path.as_ref();
    if !path.exists() {
        return;
    }

    match File::open(path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            match serde_json::from_reader::<_, HashMap<String, serde_json::Value>>(reader) {
                Ok(raw_entries) => {
                    let now = now_secs();
                    let max_stale = max_stale_secs();
                    let mut inserted = 0;
                    let mut discarded_expired = 0;
                    let mut discarded_legacy = 0;

                    for (k, val) in raw_entries {
                        let entry: CacheEntry = match serde_json::from_value(val) {
                            Ok(e) => e,
                            Err(_) => {
                                discarded_legacy += 1;
                                continue;
                            }
                        };

                        if entry.freshness_at(now, max_stale) == CacheFreshness::Expired {
                            discarded_expired += 1;
                            continue;
                        }

                        cache.insert(k, entry);
                        inserted += 1;
                    }

                    tracing::info!(
                        inserted,
                        discarded_expired,
                        discarded_legacy,
                        "[CACHE] Loaded entries from disk (pruned expired & legacy entries)"
                    );
                }
                Err(err) => {
                    tracing::warn!(error = %err, "[CACHE] Failed to deserialize cache; starting fresh");
                }
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "[CACHE] Could not open cache file");
        }
    }
}

pub async fn save_cache_to_disk_async(cache: DnsCache, path: String) {
    tokio::task::spawn_blocking(move || {
        save_cache_to_disk_sync(&cache, &path);
    })
    .await
    .unwrap_or_default();
}

pub fn save_cache_to_disk_sync<P: AsRef<Path>>(cache: &DnsCache, path: P) {
    let path = path.as_ref();
    let tmp_path = path.with_extension("tmp");
    match File::create(&tmp_path) {
        Ok(file) => {
            let writer = BufWriter::new(file);
            let now = now_secs();
            let max_stale = max_stale_secs();
            // moka's iter() yields (Arc<K>, V) where V is owned.
            let mut map: HashMap<String, CacheEntry> = HashMap::new();

            for (k, v) in cache.iter() {
                if v.freshness_at(now, max_stale) != CacheFreshness::Expired {
                    map.insert((*k).clone(), v);
                }
            }

            if let Err(err) = serde_json::to_writer(writer, &map) {
                tracing::warn!(error = %err, "[CACHE] Failed to write JSON cache to disk");
                return;
            }
            if let Err(err) = std::fs::rename(&tmp_path, path) {
                tracing::warn!(error = %err, "[CACHE] Failed to swap in new cache file");
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "[CACHE] Failed to create temp cache file on disk");
        }
    }
}
