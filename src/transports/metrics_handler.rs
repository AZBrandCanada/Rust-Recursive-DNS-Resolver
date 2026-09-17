// src/transports/metrics_handler.rs
use crate::engine::AppState;
use crate::metrics::metrics;
use crate::root_zone::current_status;

pub fn build_metrics_payload(state: &AppState) -> serde_json::Value {
    let snap = metrics().snapshot();
    let rz = current_status();

    serde_json::json!({
        "cache": {
            "entries": state.cache.entry_count(),
            "hits": snap.cache_hits,
            "misses": snap.cache_misses,
            "insertions": snap.cache_insertions,
            "evictions": snap.cache_evictions,
            "hit_ratio": snap.hit_ratio(),
            "stale_served": snap.stale_served,
        },
        "negative_cache": {
            "hits": snap.negative_hits,
            "insertions": snap.negative_insertions,
        },
        "singleflight": {
            "leaders": snap.singleflight_leader,
            "coalesced": snap.singleflight_coalesced,
            "in_flight": state.singleflight.in_flight_count(),
        },
        "prefetch": {
            "attempts": snap.prefetch_attempts,
            "success": snap.prefetch_success,
            "failure": snap.prefetch_failure,
        },
        "root_zone": {
            "state": format!("{:?}", rz.state),
            "serial": rz.serial,
            "loaded_at": rz.loaded_at,
            "tld_count": rz.tld_count,
            "file_age_days": rz.file_age_days,
            "source_path": rz.source_path,
            "source_url": rz.source_url,
            "last_refresh_attempt": rz.last_refresh_attempt,
            "last_refresh_success": rz.last_refresh_success,
            "consecutive_failures": rz.consecutive_failures,
        },
    })
}
