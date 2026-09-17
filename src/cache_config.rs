// src/cache_config.rs
//
// Centralized cache configuration. Read once at startup from the
// environment. Follows the existing project pattern (env vars, no new
// config system).

use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Master switch. When false, cache reads and writes are skipped
    /// entirely. Single-flight still applies so concurrent misses are
    /// still coalesced. Useful for A/B correctness testing.
    pub enabled: bool,

    /// Maximum number of answer/negative entries. moka evicts by
    /// W-TinyLFU once this is exceeded.
    pub max_answer_entries: u64,

    /// Whether to run background refreshes for hot records nearing
    /// expiration.
    pub prefetch_enabled: bool,

    /// Refresh threshold as a percentage of original TTL. When a hit
    /// arrives and remaining TTL < threshold%, the record is eligible
    /// for background refresh (subject to prefetch_min_hits).
    pub prefetch_threshold_pct: u8,

    /// Minimum hit count before a record is considered "hot" enough
    /// to warrant background refresh.
    pub prefetch_min_hits: u64,
}

pub fn cache_config() -> &'static CacheConfig {
    static CFG: OnceLock<CacheConfig> = OnceLock::new();
    CFG.get_or_init(|| CacheConfig {
        enabled: env_bool("CACHE_ENABLED", true),
        max_answer_entries: env_u64("CACHE_MAX_ENTRIES", 500_000),
        prefetch_enabled: env_bool("CACHE_PREFETCH", true),
        prefetch_threshold_pct: env_u64("CACHE_PREFETCH_THRESHOLD_PCT", 15).min(90) as u8,
        prefetch_min_hits: env_u64("CACHE_PREFETCH_MIN_HITS", 5),
    })
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off" | ""))
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}