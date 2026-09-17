// src/engine/resolve.rs
use super::query::parse_and_validate_query;
use super::response::{
    calculate_cache_ttl, construct_client_response, is_cacheable, is_cacheable_dnssec,
    make_servfail_wire, make_truncated_wire,
};
use crate::cache::{now_secs, CacheEntry, CacheFreshness, DnsCache, EntryKind};
use crate::cache_config::cache_config;
use crate::dnssec::{DnssecStatus, DnssecValidator};
use crate::metrics::metrics;
use crate::ratelimit::{RateLimiter, RrlAction};
use crate::recursor::{RecursorError, RecursiveResolver};
use crate::singleflight::SingleFlight;
use dashmap::DashMap;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

/// Canonical resolution result. Handed to single-flight waiters and
/// then adapted per-client (AD bit, DO filtering, EDNS sizing).
#[derive(Clone)]
pub struct Resolved {
    pub msg: Message,
    pub status: DnssecStatus,
    pub cached_at: u64,
    pub kind: EntryKind,
}

#[derive(Clone)]
pub struct AppState {
    pub cache: DnsCache,
    pub recursor: Arc<RecursiveResolver>,
    pub rate_limiter: Arc<RateLimiter>,
    pub dnssec_enforce: bool,
    /// Single-flight for the miss path. Coalesces concurrent identical
    /// (qname, qtype, class) misses into one upstream resolution.
    pub singleflight: Arc<SingleFlight<Option<Resolved>>>,
    /// Narrower gate used only for stale revalidation. Kept distinct
    /// so a stale revalidation doesn't block a live miss on a
    /// different record or vice versa.
    pub in_flight: Arc<DashMap<String, ()>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    Success(Vec<u8>),
    ServFail(Vec<u8>),
    Truncated(Vec<u8>),
    Dropped,
    Malformed,
}

pub async fn process_dns_query(
    req_wire: &[u8],
    state: &AppState,
    protocol: &'static str,
    client_ip: IpAddr,
) -> ProcessOutcome {
    let start = Instant::now();
    let parsed = match parse_and_validate_query(req_wire, protocol, client_ip) {
        Ok(p) => p,
        Err(outcome) => return outcome,
    };

    let req_msg = parsed.req_msg;
    let qname = parsed.qname;
    let qtype = parsed.qtype;
    let client_max_payload = parsed.client_max_payload;
    let client_dnssec_ok = parsed.client_dnssec_ok;
    let cache_key = parsed.cache_key;
    let query = &req_msg.queries()[0];

    // Rate Limiting check
    match state
        .rate_limiter
        .check_query(protocol, client_ip, &qname, qtype)
    {
        RrlAction::Allow => {}
        RrlAction::Truncate => {
            tracing::warn!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                "[SECURITY] Challenging client with TC=1"
            );
            return ProcessOutcome::Truncated(make_truncated_wire(req_msg.id(), Some(query)));
        }
        RrlAction::Drop => {
            tracing::warn!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                "[SECURITY] Rate limit dropped"
            );
            return ProcessOutcome::Dropped;
        }
    }

    let now = now_secs();
    let cfg = cache_config();

    // 1. Cache hit path (skipped entirely when cache is disabled).
    if cfg.enabled {
        if let Some(entry) = state.cache.get(&cache_key) {
            let freshness = entry.freshness(now);

            if freshness != CacheFreshness::Expired {
                metrics().cache_hits.fetch_add(1, Ordering::Relaxed);
                if entry.kind == EntryKind::Negative {
                    metrics().negative_hits.fetch_add(1, Ordering::Relaxed);
                }
                if freshness == CacheFreshness::Stale {
                    metrics().stale_served.fetch_add(1, Ordering::Relaxed);

                    if state.in_flight.insert(cache_key.clone(), ()).is_none() {
                        let cache_clone = state.cache.clone();
                        let recursor_clone = state.recursor.clone();
                        let key_clone = cache_key.clone();
                        let name_clone = qname.clone();
                        let in_flight_clone = state.in_flight.clone();

                        tokio::spawn(async move {
                            if let Ok(mut fresh_msg) =
                                recursor_clone.resolve(&name_clone, qtype).await
                            {
                                let status = DnssecValidator::validate_message(
                                    &recursor_clone,
                                    &fresh_msg,
                                    &name_clone,
                                    qtype,
                                )
                                .await;

                                match status {
                                    DnssecStatus::Secure => {
                                        fresh_msg.set_authentic_data(true);
                                    }
                                    DnssecStatus::InsecureUnsigned
                                    | DnssecStatus::InsecureUnknown => {
                                        fresh_msg.set_authentic_data(false);
                                    }
                                    DnssecStatus::Bogus => {
                                        tracing::warn!(
                                            domain = %name_clone,
                                            rtype = %qtype,
                                            "[DNSSEC] Bogus response during stale revalidation; keeping previous cache entry"
                                        );
                                        in_flight_clone.remove(&key_clone);
                                        return;
                                    }
                                }

                                if is_cacheable(&fresh_msg) && is_cacheable_dnssec(status) {
                                    fresh_msg.set_authoritative(false);
                                    fresh_msg.set_recursion_available(true);
                                    if let Ok(wire) = fresh_msg.to_bytes() {
                                        let cur_time = now_secs();
                                        let ttl = calculate_cache_ttl(&fresh_msg, status, cur_time);

                                        if ttl > 0 {
                                            let kind = if fresh_msg.response_code()
                                                == ResponseCode::NXDomain
                                                || (fresh_msg.response_code()
                                                    == ResponseCode::NoError
                                                    && fresh_msg.answers().is_empty())
                                            {
                                                EntryKind::Negative
                                            } else {
                                                EntryKind::Positive
                                            };

                                            cache_clone.insert(
                                                key_clone.clone(),
                                                CacheEntry {
                                                    raw_wire: wire,
                                                    min_ttl: ttl,
                                                    cached_at: cur_time,
                                                    last_revalidated_at: cur_time,
                                                    dnssec_status: status,
                                                    kind,
                                                },
                                            );
                                            metrics()
                                                .cache_insertions
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                } else if let Some(mut existing) = cache_clone.get(&key_clone) {
                                    existing.last_revalidated_at = now_secs();
                                    cache_clone.insert(key_clone.clone(), existing);
                                }
                            }
                            in_flight_clone.remove(&key_clone);
                        });
                    }
                }

                let mut decoder = BinDecoder::new(&entry.raw_wire);
                if let Ok(cached_msg) = Message::read(&mut decoder) {
                    let cached_status = entry.dnssec_status;

                    if let Some(wire) = construct_client_response(
                        &cached_msg,
                        qtype,
                        cached_status,
                        freshness,
                        entry.cached_at,
                        &req_msg,
                        client_max_payload,
                        client_dnssec_ok,
                        now,
                    ) {
                        if state.rate_limiter.should_challenge_large_response(
                            protocol,
                            client_ip,
                            wire.len(),
                            client_max_payload,
                        ) {
                            return ProcessOutcome::Truncated(make_truncated_wire(
                                req_msg.id(),
                                Some(query),
                            ));
                        }

                        return ProcessOutcome::Success(wire);
                    }
                }
            } else {
                metrics().cache_misses.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            metrics().cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        metrics().cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    // 2. Cache miss path (or cache disabled).

    let resolved = if !cfg.enabled {
        match resolve_and_validate(state, &qname, qtype).await {
            Ok(r) => r,
            Err(err) => {
                tracing::error!(
                    protocol,
                    client = %client_ip,
                    domain = %qname,
                    rtype = %qtype,
                    error = %err,
                    "[ERROR] Recursive resolution failed; returning SERVFAIL"
                );
                return ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), Some(query)));
            }
        }
    } else {
        // Single-flight: coalesce concurrent identical misses.
        let key = cache_key.clone();
        let sf = state.singleflight.clone();
        let state_for_closure = state.clone();
        let qname_for_closure = qname.clone();

        let (result, is_leader) = sf
            .run(key, move || async move {
                match resolve_and_validate(&state_for_closure, &qname_for_closure, qtype).await {
                    Ok(r) => Some(r),
                    Err(_) => None,
                }
            })
            .await;

        if is_leader {
            metrics().singleflight_leader.fetch_add(1, Ordering::Relaxed);
        } else {
            metrics()
                .singleflight_coalesced
                .fetch_add(1, Ordering::Relaxed);
        }

        match result {
            Some(r) => r,
            None => {
                tracing::error!(
                    protocol,
                    client = %client_ip,
                    domain = %qname,
                    rtype = %qtype,
                    "[ERROR] Recursive resolution failed; returning SERVFAIL"
                );
                return ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), Some(query)));
            }
        }
    };

    // DNSSEC enforcement (client-specific: the client's CD bit matters).
    let client_cd = req_msg.checking_disabled();

    match resolved.status {
        DnssecStatus::Bogus if state.dnssec_enforce && !client_cd => {
            tracing::warn!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                "[DNSSEC] Bogus DNSSEC proof; returning SERVFAIL"
            );
            return ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), Some(query)));
        }
        DnssecStatus::Bogus if client_cd => {
            tracing::debug!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                "[DNSSEC] Bogus proof but client set CD=1; serving with AD=0"
            );
        }
        DnssecStatus::Bogus => {
            tracing::warn!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                "[DNSSEC] Bogus DNSSEC proof; enforcement disabled, serving with AD=0"
            );
        }
        _ => {}
    }

    let wire = match construct_client_response(
        &resolved.msg,
        qtype,
        resolved.status,
        CacheFreshness::Fresh,
        resolved.cached_at,
        &req_msg,
        client_max_payload,
        client_dnssec_ok,
        now,
    ) {
        Some(w) => w,
        None => {
            return ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), Some(query)));
        }
    };

    tracing::info!(
        protocol,
        client = %client_ip,
        domain = %qname,
        rtype = %qtype,
        latency_ms = start.elapsed().as_millis(),
        "[RESOLVED] Resolution completed"
    );

    if state.rate_limiter.should_challenge_large_response(
        protocol,
        client_ip,
        wire.len(),
        client_max_payload,
    ) {
        return ProcessOutcome::Truncated(make_truncated_wire(req_msg.id(), Some(query)));
    }

    ProcessOutcome::Success(wire)
}

/// Canonical resolution + validation + cache insert. Called at most
/// once per unique cache key at a time by single-flight.
async fn resolve_and_validate(
    state: &AppState,
    qname: &Name,
    qtype: RecordType,
) -> Result<Resolved, RecursorError> {
    let mut resp_msg = state.recursor.resolve(qname, qtype).await?;

    let dnssec_status =
        DnssecValidator::validate_message(&state.recursor, &resp_msg, qname, qtype).await;

    resp_msg.set_authentic_data(dnssec_status == DnssecStatus::Secure);
    resp_msg.set_authoritative(false);
    resp_msg.set_recursion_available(true);

    let now = now_secs();

    let kind = if resp_msg.response_code() == ResponseCode::NXDomain
        || (resp_msg.response_code() == ResponseCode::NoError && resp_msg.answers().is_empty())
    {
        EntryKind::Negative
    } else {
        EntryKind::Positive
    };

    let cache_key = format!("{}:{}:IN", qname.to_ascii().to_lowercase(), qtype);

    if cache_config().enabled && is_cacheable(&resp_msg) && is_cacheable_dnssec(dnssec_status) {
        if let Ok(canonical_wire) = resp_msg.to_bytes() {
            let ttl = calculate_cache_ttl(&resp_msg, dnssec_status, now);
            if ttl > 0 {
                state.cache.insert(
                    cache_key,
                    CacheEntry {
                        raw_wire: canonical_wire,
                        min_ttl: ttl,
                        cached_at: now,
                        last_revalidated_at: now,
                        dnssec_status,
                        kind,
                    },
                );
                metrics().cache_insertions.fetch_add(1, Ordering::Relaxed);
                if kind == EntryKind::Negative {
                    metrics()
                        .negative_insertions
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    } else if dnssec_status == DnssecStatus::InsecureUnknown {
        tracing::debug!(
            domain = %qname,
            rtype = %qtype,
            "[DNSSEC] InsecureUnknown verdict; serving without caching"
        );
    }

    Ok(Resolved {
        msg: resp_msg,
        status: dnssec_status,
        cached_at: now,
        kind,
    })
}
