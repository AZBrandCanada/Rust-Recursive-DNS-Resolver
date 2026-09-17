// src/hit_tracker.rs
//
// Per-key popularity tracking. Used only by the prefetch loop to
// decide which records are "hot" enough to warrant a background
// refresh as they near expiration.
//
// Bounded by HIT_TRACKER_MAX_ENTRIES. When the bound is reached new
// keys are dropped rather than evicting (cold keys will not re-enter
// on their own once pruned). This trades a small loss of coverage for
// O(1) inserts and zero mutex contention.

use crate::cache::now_secs;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;

pub struct HitInfo {
    pub count: AtomicU32,
    pub last_seen: AtomicU64,
    pub last_prefetch_attempt: AtomicU64,
    pub consecutive_failures: AtomicU32,
}

pub struct HitTracker {
    entries: DashMap<String, HitInfo>,
    max_entries: usize,
}

impl HitTracker {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            max_entries,
        }
    }

    pub fn record(&self, key: &str) {
        let now = now_secs();
        match self.entries.get(key) {
            Some(hit) => {
                let _ = hit
                    .count
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        if v == u32::MAX {
                            None
                        } else {
                            Some(v + 1)
                        }
                    });
                hit.last_seen.store(now, Ordering::Relaxed);
            }
            None => {
                if self.entries.len() >= self.max_entries {
                    return;
                }
                self.entries.insert(
                    key.to_string(),
                    HitInfo {
                        count: AtomicU32::new(1),
                        last_seen: AtomicU64::new(now),
                        last_prefetch_attempt: AtomicU64::new(0),
                        consecutive_failures: AtomicU32::new(0),
                    },
                );
            }
        }
    }

    pub fn reset_count(&self, key: &str) {
        if let Some(hit) = self.entries.get(key) {
            hit.count.store(0, Ordering::Relaxed);
        }
    }

    pub fn record_prefetch_success(&self, key: &str) {
        if let Some(hit) = self.entries.get(key) {
            hit.last_prefetch_attempt
                .store(now_secs(), Ordering::Relaxed);
            hit.consecutive_failures.store(0, Ordering::Relaxed);
            hit.count.store(0, Ordering::Relaxed);
        }
    }

    pub fn record_prefetch_failure(&self, key: &str) {
        if let Some(hit) = self.entries.get(key) {
            hit.last_prefetch_attempt
                .store(now_secs(), Ordering::Relaxed);
            let _ =
                hit.consecutive_failures
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        if v == u32::MAX {
                            None
                        } else {
                            Some(v + 1)
                        }
                    });
        }
    }

    fn backoff_secs(&self, key: &str) -> u64 {
        let failures = self
            .entries
            .get(key)
            .map(|h| h.consecutive_failures.load(Ordering::Relaxed))
            .unwrap_or(0);
        // 60s, 120s, 240s, ..., capped at 3600s.
        let shift = failures.min(6);
        (60u64 << shift).min(3600)
    }

    /// Returns true if the key is due for a prefetch attempt: has
    /// enough hits and is not within the exponential backoff window
    /// after a prior failure.
    pub fn should_prefetch(&self, key: &str, now: u64, min_hits: u32) -> bool {
        let Some(hit) = self.entries.get(key) else {
            return false;
        };

        if hit.count.load(Ordering::Relaxed) < min_hits {
            return false;
        }

        let last = hit.last_prefetch_attempt.load(Ordering::Relaxed);
        if last > 0 {
            let backoff = self.backoff_secs(key);
            if now.saturating_sub(last) < backoff {
                return false;
            }
        }

        true
    }

    pub fn keys_snapshot(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.key().clone()).collect()
    }

    pub fn prune(&self, max_idle_secs: u64) {
        let now = now_secs();
        self.entries
            .retain(|_, v| now.saturating_sub(v.last_seen.load(Ordering::Relaxed)) < max_idle_secs);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

pub fn hit_tracker() -> &'static HitTracker {
    static TRACKER: OnceLock<HitTracker> = OnceLock::new();
    TRACKER.get_or_init(|| {
        let max = std::env::var("HIT_TRACKER_MAX_ENTRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100_000);
        HitTracker::new(max)
    })
}
