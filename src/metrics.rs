// src/metrics.rs
//
// Process-wide atomic counters for cache and single-flight behavior.
// Exposed via a snapshot() call. No external metrics crate — plain
// atomics are sufficient for the counts we need and keep the
// dependency footprint small.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

#[derive(Default)]
pub struct Metrics {
    // Answer cache
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_insertions: AtomicU64,
    pub cache_evictions: AtomicU64,
    pub stale_served: AtomicU64,

    // Negative cache (subset of the answer cache tagged Negative)
    pub negative_hits: AtomicU64,
    pub negative_insertions: AtomicU64,

    // Delegation & DNSSEC (counted from existing caches)
    pub delegation_hits: AtomicU64,
    pub dnssec_hits: AtomicU64,

    // Single-flight
    pub singleflight_leader: AtomicU64,
    pub singleflight_coalesced: AtomicU64,

    // Prefetch
    pub prefetch_attempts: AtomicU64,
    pub prefetch_success: AtomicU64,
    pub prefetch_failure: AtomicU64,
}

pub fn metrics() -> &'static Metrics {
    static M: OnceLock<Metrics> = OnceLock::new();
    M.get_or_init(Metrics::default)
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            cache_insertions: self.cache_insertions.load(Ordering::Relaxed),
            cache_evictions: self.cache_evictions.load(Ordering::Relaxed),
            stale_served: self.stale_served.load(Ordering::Relaxed),
            negative_hits: self.negative_hits.load(Ordering::Relaxed),
            negative_insertions: self.negative_insertions.load(Ordering::Relaxed),
            delegation_hits: self.delegation_hits.load(Ordering::Relaxed),
            dnssec_hits: self.dnssec_hits.load(Ordering::Relaxed),
            singleflight_leader: self.singleflight_leader.load(Ordering::Relaxed),
            singleflight_coalesced: self.singleflight_coalesced.load(Ordering::Relaxed),
            prefetch_attempts: self.prefetch_attempts.load(Ordering::Relaxed),
            prefetch_success: self.prefetch_success.load(Ordering::Relaxed),
            prefetch_failure: self.prefetch_failure.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct MetricsSnapshot {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_insertions: u64,
    pub cache_evictions: u64,
    pub stale_served: u64,
    pub negative_hits: u64,
    pub negative_insertions: u64,
    pub delegation_hits: u64,
    pub dnssec_hits: u64,
    pub singleflight_leader: u64,
    pub singleflight_coalesced: u64,
    pub prefetch_attempts: u64,
    pub prefetch_success: u64,
    pub prefetch_failure: u64,
}

impl MetricsSnapshot {
    pub fn hit_ratio(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }
}
