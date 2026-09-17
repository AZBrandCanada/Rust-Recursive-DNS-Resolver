// src/prefetch.rs
//
// Background prefetch for hot records nearing expiration.
//
// Every 10 seconds:
//   1. Prune idle entries from the hit tracker.
//   2. Snapshot the tracked keys.
//   3. For each key whose cache entry is fresh but within
//      CACHE_PREFETCH_THRESHOLD_PCT of expiration and whose hit count
//      meets CACHE_PREFETCH_MIN_HITS, spawn a refresh.
//
// Refreshes go through the SAME single-flight key as a live miss,
// so a query arriving during prefetch coalesces with it. Jitter (both
// a random subset per tick and a random pre-flight delay) prevents
// synchronised bursts. Exponential backoff after failure prevents
// hammering unavailable authoritative servers.

use crate::cache::{now_secs, CacheFreshness};
use crate::cache_config::cache_config;
use crate::engine::resolve::{resolve_and_validate, AppState};
use crate::hit_tracker::hit_tracker;
use crate::metrics::metrics;
use hickory_proto::rr::{Name, RecordType};
use rand::Rng;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

const TICK_SECS: u64 = 10;
const MAX_CONCURRENT_PREFETCH: usize = 16;
const TRACKER_IDLE_PRUNE_SECS: u64 = 600;
const JITTER_MAX_MS: u64 = 2000;
const PER_TICK_ACCEPT_PROB: f64 = 0.5;

pub async fn prefetch_loop(state: AppState) {
    let cfg = cache_config();
    if !cfg.prefetch_enabled {
        tracing::info!("[PREFETCH] disabled by configuration");
        return;
    }

    tracing::info!(
        threshold_pct = cfg.prefetch_threshold_pct,
        min_hits = cfg.prefetch_min_hits,
        "[PREFETCH] background loop started"
    );

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_PREFETCH));
    let mut interval = tokio::time::interval(Duration::from_secs(TICK_SECS));
    interval.tick().await;

    loop {
        interval.tick().await;

        let now = now_secs();
        let tracker = hit_tracker();
        tracker.prune(TRACKER_IDLE_PRUNE_SECS);

        let keys = tracker.keys_snapshot();
        if keys.is_empty() {
            continue;
        }

        let threshold_pct = cfg.prefetch_threshold_pct as u64;
        let min_hits = cfg.prefetch_min_hits as u32;

        let mut candidates: Vec<String> = Vec::new();

        for key in keys {
            let Some(entry) = state.cache.get(&key) else {
                tracker.reset_count(&key);
                continue;
            };

            if entry.freshness(now) != CacheFreshness::Fresh {
                continue;
            }

            let total = entry.min_ttl as u64;
            if total == 0 {
                continue;
            }
            let age = now.saturating_sub(entry.cached_at);
            let remaining = total.saturating_sub(age);
            let threshold = (total * threshold_pct) / 100;
            if remaining > threshold {
                continue;
            }

            if !tracker.should_prefetch(&key, now, min_hits) {
                continue;
            }

            // Spread refreshes across ticks by taking a random
            // subset of eligible keys per tick.
            if !rand::thread_rng().gen_bool(PER_TICK_ACCEPT_PROB) {
                continue;
            }

            candidates.push(key);
        }

        if candidates.is_empty() {
            continue;
        }

        tracing::debug!(
            count = candidates.len(),
            tracked = tracker.len(),
            "[PREFETCH] tick"
        );

        for key in candidates {
            let parts: Vec<&str> = key.splitn(3, ':').collect();
            if parts.len() != 3 {
                continue;
            }
            let Ok(name) = Name::from_str(parts[0]) else {
                continue;
            };
            let Ok(qtype) = RecordType::from_str(parts[1]) else {
                continue;
            };

            let Ok(permit) = sem.clone().try_acquire_owned() else {
                // Too many prefetches in flight; skip this key this tick.
                // It will be reconsidered next tick.
                break;
            };

            let state_ref = state.clone();
            let key_ref = key.clone();
            let tracker_ref = hit_tracker();

            metrics().prefetch_attempts.fetch_add(1, Ordering::Relaxed);

            tokio::spawn(async move {
                let _permit = permit;

                // Random pre-flight delay spreads traffic across the
                // tick window and avoids synchronized refresh bursts
                // after a restart or cache warmup.
                let delay_ms = rand::thread_rng().gen_range(0..JITTER_MAX_MS);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;

                let sf = state_ref.singleflight.clone();
                let state_for_closure = state_ref.clone();
                let name_for_closure = name.clone();
                let sf_key = key_ref.clone();

                let (result, is_leader) = sf
                    .run(sf_key, move || async move {
                        resolve_and_validate(&state_for_closure, &name_for_closure, qtype)
                            .await
                            .ok()
                    })
                    .await;

                if !is_leader {
                    // A live miss on the same key is already doing the
                    // work; nothing to do here.
                    return;
                }

                match result {
                    Some(_) => {
                        metrics().prefetch_success.fetch_add(1, Ordering::Relaxed);
                        tracker_ref.record_prefetch_success(&key_ref);
                    }
                    None => {
                        metrics().prefetch_failure.fetch_add(1, Ordering::Relaxed);
                        tracker_ref.record_prefetch_failure(&key_ref);
                    }
                }
            });
        }
    }
}
