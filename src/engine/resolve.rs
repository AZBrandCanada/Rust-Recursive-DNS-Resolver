// src/engine/resolve.rs
use super::query::parse_and_validate_query;
use super::response::{
    calculate_cache_ttl, construct_client_response, is_cacheable, is_cacheable_dnssec,
    make_servfail_wire, make_truncated_wire,
};
use crate::cache::{now_secs, CacheEntry, CacheFreshness, DnsCache};
use crate::dnssec::{DnssecStatus, DnssecValidator};
use crate::ratelimit::{RateLimiter, RrlAction};
use crate::recursor::RecursiveResolver;
use dashmap::DashMap;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct AppState {
    pub cache: DnsCache,
    pub recursor: Arc<RecursiveResolver>,
    pub rate_limiter: Arc<RateLimiter>,
    pub dnssec_enforce: bool,
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

    // 1. Cache hit path
    if let Some(entry) = state.cache.get(&cache_key) {
        let freshness = entry.freshness(now);

        if freshness != CacheFreshness::Expired {
            if freshness == CacheFreshness::Stale
                && state.in_flight.insert(cache_key.clone(), ()).is_none()
            {
                let cache_clone = state.cache.clone();
                let recursor_clone = state.recursor.clone();
                let key_clone = cache_key.clone();
                let name_clone = qname.clone();
                let in_flight_clone = state.in_flight.clone();

                tokio::spawn(async move {
                    if let Ok(mut fresh_msg) = recursor_clone.resolve(&name_clone, qtype).await {
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
                            DnssecStatus::InsecureUnsigned | DnssecStatus::InsecureUnknown => {
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

                                cache_clone.insert(
                                    key_clone.clone(),
                                    CacheEntry {
                                        raw_wire: wire,
                                        min_ttl: ttl,
                                        cached_at: cur_time,
                                        last_revalidated_at: cur_time,
                                        dnssec_status: status,
                                    },
                                );
                            }
                        } else if let Some(mut existing) = cache_clone.get_mut(&key_clone) {
                            existing.last_revalidated_at = now_secs();
                        }
                    }
                    in_flight_clone.remove(&key_clone);
                });
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
        }
    }

    // 2. Cache miss path (or Expired stale fallback)
    match state.recursor.resolve(&qname, qtype).await {
        Ok(mut resp_msg) => {
            let dnssec_status =
                DnssecValidator::validate_message(&state.recursor, &resp_msg, &qname, qtype).await;

            let client_cd = req_msg.checking_disabled();

            match dnssec_status {
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

            resp_msg.set_authentic_data(dnssec_status == DnssecStatus::Secure);
            resp_msg.set_authoritative(false);
            resp_msg.set_recursion_available(true);

            if is_cacheable(&resp_msg) && is_cacheable_dnssec(dnssec_status) {
                if let Ok(canonical_wire) = resp_msg.to_bytes() {
                    let ttl = calculate_cache_ttl(&resp_msg, dnssec_status, now);

                    state.cache.insert(
                        cache_key,
                        CacheEntry {
                            raw_wire: canonical_wire,
                            min_ttl: ttl,
                            cached_at: now,
                            last_revalidated_at: now,
                            dnssec_status,
                        },
                    );
                }
            } else if dnssec_status == DnssecStatus::InsecureUnknown {
                tracing::debug!(
                    protocol,
                    client = %client_ip,
                    domain = %qname,
                    rtype = %qtype,
                    "[DNSSEC] InsecureUnknown verdict; serving without caching"
                );
            }

            let wire = match construct_client_response(
                &resp_msg,
                qtype,
                dnssec_status,
                CacheFreshness::Fresh,
                now,
                &req_msg,
                client_max_payload,
                client_dnssec_ok,
                now,
            ) {
                Some(w) => w,
                None => {
                    return ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), Some(query)))
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
        Err(err) => {
            tracing::error!(
                protocol,
                client = %client_ip,
                domain = %qname,
                rtype = %qtype,
                error = %err,
                "[ERROR] Recursive resolution failed; returning SERVFAIL"
            );
            ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), Some(query)))
        }
    }
}
