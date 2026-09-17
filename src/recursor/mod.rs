// src/recursor/mod.rs
pub mod cname;
pub mod delegation;
pub mod dname;
pub mod upstream;

use cname::{extract_cname_target, merge_redirection_response};
use delegation::{delegation_ttl, find_cached_start, purge_delegation};
pub use delegation::{DelegationEntry, DelegationSource};
pub use dname::{dname_substitute, extract_dname_target, DNAME_RECORD_TYPE};
use upstream::{filter_safe_ips, is_safe_upstream_ip, query_servers_with_fallback, ROOT_SERVERS};

use crate::cache::now_secs;
use dashmap::DashMap;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;

pub const MAX_DEPTH: usize = 16;
pub const MAX_STEPS: usize = 16;

#[derive(Debug, Error)]
pub enum RecursorError {
    #[error("Maximum recursion depth exceeded")]
    DepthExceeded,
    #[error("Maximum resolution steps exceeded")]
    StepLimitExceeded,
    #[error("All nameservers timed out or failed to respond")]
    AllNameserversFailed,
    #[error("Failed to resolve nameserver glue IP")]
    GlueResolutionFailed,
    #[error("Delegation made no forward progress or loop detected")]
    NoProgress,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("DNS Protocol error: {0}")]
    Proto(#[from] hickory_proto::ProtoError),
    #[error("DNS Decode error: {0}")]
    Decode(#[from] hickory_proto::serialize::binary::DecodeError),
}

pub struct RecursiveResolver {
    delegation_cache: DashMap<String, DelegationEntry>,
}

impl RecursiveResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            delegation_cache: DashMap::new(),
        })
    }

    pub async fn resolve(&self, name: &Name, rtype: RecordType) -> Result<Message, RecursorError> {
        let mut visited: HashSet<String> = HashSet::new();
        self.resolve_internal(name, rtype, 0, &mut visited).await
    }

    /// Read-only access to the delegation cache. Used by the root
    /// zone loader to pre-populate TLD delegations at startup.
    pub fn delegation_cache(&self) -> &DashMap<String, DelegationEntry> {
        &self.delegation_cache
    }

    fn purge_delegation_for(&self, name: &Name, rtype: RecordType) {
        purge_delegation(&self.delegation_cache, name, rtype);
    }

    fn resolve_internal<'a>(
        &'a self,
        name: &'a Name,
        rtype: RecordType,
        depth: usize,
        visited: &'a mut HashSet<String>,
    ) -> Pin<Box<dyn Future<Output = Result<Message, RecursorError>> + Send + 'a>> {
        Box::pin(async move {
            if depth > MAX_DEPTH {
                return Err(RecursorError::DepthExceeded);
            }

            let mut using_cached = false;
            let start_ips = find_cached_start(&self.delegation_cache, name, rtype);
            let mut current_servers: Vec<SocketAddr> = match start_ips {
                Some(ips) if !ips.is_empty() => {
                    using_cached = true;
                    ips.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect()
                }
                _ => ROOT_SERVERS
                    .iter()
                    .filter_map(|ip| ip.parse().ok())
                    .map(|ip| SocketAddr::new(ip, 53))
                    .collect(),
            };

            let mut last_zone: Option<Name> = None;
            let mut bailiwick: Name = Name::root();

            for _step in 0..MAX_STEPS {
                let response = match query_servers_with_fallback(&current_servers, name, rtype)
                    .await
                {
                    Some(r) => r,
                    None => {
                        if using_cached {
                            tracing::warn!(
                                name = %name,
                                "[RECURSOR] Cached delegation servers failed or refused; purging cache and retrying from root"
                            );
                            using_cached = false;
                            self.purge_delegation_for(name, rtype);
                            current_servers = ROOT_SERVERS
                                .iter()
                                .filter_map(|ip| ip.parse().ok())
                                .map(|ip| SocketAddr::new(ip, 53))
                                .collect();
                            last_zone = None;
                            bailiwick = Name::root();
                            continue;
                        }
                        return Err(RecursorError::AllNameserversFailed);
                    }
                };

                using_cached = false;

                // 1. Exact positive answer, CNAME, or DNAME redirection
                if !response.answers().is_empty() {
                    let has_target_type = response
                        .answers()
                        .iter()
                        .any(|r| r.name() == name && r.record_type() == rtype);

                    if has_target_type {
                        return Ok(response);
                    }

                    // A. Check for CNAME
                    let cname_target = response
                        .answers()
                        .iter()
                        .find_map(|r| extract_cname_target(r, name));

                    if let Some(first_target) = cname_target {
                        let mut current_target = first_target;
                        let mut cname_seen = HashSet::new();
                        cname_seen.insert(name.to_string().to_lowercase());

                        loop {
                            let key = current_target.to_string().to_lowercase();
                            if !cname_seen.insert(key) {
                                tracing::warn!(target = %current_target, "[RECURSOR] CNAME loop in answer section; aborting");
                                return Err(RecursorError::NoProgress);
                            }

                            let target_in_answers = response
                                .answers()
                                .iter()
                                .any(|r| r.name() == &current_target && r.record_type() == rtype);

                            if target_in_answers {
                                return Ok(response);
                            }

                            let next_cname = response
                                .answers()
                                .iter()
                                .find_map(|r| extract_cname_target(r, &current_target));

                            match next_cname {
                                Some(next) => current_target = next,
                                None => break,
                            }
                        }

                        let key = format!("cname:{}", current_target.to_string().to_lowercase());
                        if visited.contains(&key) {
                            tracing::warn!(target = %current_target, "[RECURSOR] CNAME loop detected; aborting");
                            return Err(RecursorError::NoProgress);
                        }
                        visited.insert(key);

                        let cname_resp = self
                            .resolve_internal(&current_target, rtype, depth + 1, visited)
                            .await?;

                        return Ok(merge_redirection_response(
                            name, rtype, &response, cname_resp,
                        ));
                    }

                    // B. Check for DNAME
                    let dname_match = response.answers().iter().find_map(|r| {
                        if r.record_type() == DNAME_RECORD_TYPE
                            && r.name().zone_of(name)
                            && r.name() != name
                        {
                            if let Some(target) = extract_dname_target(r) {
                                return Some((r.name().clone(), target, r.ttl()));
                            }
                        }
                        None
                    });

                    if let Some((dname_owner, target, dname_ttl)) = dname_match {
                        match dname_substitute(name, &dname_owner, &target) {
                            Ok(substituted) => {
                                let has_synth_cname = response.answers().iter().any(|r| {
                                    r.name() == name && r.record_type() == RecordType::CNAME
                                });

                                let mut working_response = response.clone();
                                if !has_synth_cname {
                                    let synth = Record::from_rdata(
                                        name.clone(),
                                        dname_ttl,
                                        RData::CNAME(CNAME(substituted.clone())),
                                    );
                                    working_response.add_answer(synth);
                                }

                                let substituted_in_answers = working_response
                                    .answers()
                                    .iter()
                                    .any(|r| r.name() == &substituted && r.record_type() == rtype);

                                if substituted_in_answers {
                                    return Ok(working_response);
                                }

                                let key =
                                    format!("dname:{}", substituted.to_string().to_lowercase());
                                if visited.contains(&key) {
                                    tracing::warn!(target = %substituted, "[RECURSOR] DNAME loop detected; aborting");
                                    return Err(RecursorError::NoProgress);
                                }
                                visited.insert(key);

                                let dname_resp = self
                                    .resolve_internal(&substituted, rtype, depth + 1, visited)
                                    .await?;

                                return Ok(merge_redirection_response(
                                    name,
                                    rtype,
                                    &working_response,
                                    dname_resp,
                                ));
                            }
                            Err(ResponseCode::YXDomain) => {
                                tracing::warn!(
                                    name = %name,
                                    dname = %dname_owner,
                                    target = %target,
                                    "[RECURSOR] DNAME synthesis resulted in oversized domain name; returning YXDOMAIN"
                                );
                                let mut yx_msg = response.clone();
                                yx_msg.set_response_code(ResponseCode::YXDomain);
                                return Ok(yx_msg);
                            }
                            Err(_) => return Err(RecursorError::NoProgress),
                        }
                    }
                }

                // 2. Authoritative terminal responses
                let authoritative_soa = response.name_servers().iter().find_map(|r| {
                    if matches!(r.data(), RData::SOA(_)) {
                        Some(r.name())
                    } else {
                        None
                    }
                });

                if let Some(soa_zone) = authoritative_soa {
                    let is_soa_authoritative = soa_zone.zone_of(name)
                        || soa_zone == name
                        || (rtype == RecordType::DS
                            && (name.zone_of(soa_zone) || soa_zone.zone_of(name)));

                    if is_soa_authoritative {
                        return Ok(response);
                    }
                }

                // RFC 2181 §6.1: An authoritative response (AA=1) is never a
                // referral. Both NXDomain and empty NoError (NODATA) must
                // terminate recursion cleanly.
                if response.authoritative()
                    && (response.response_code() == ResponseCode::NXDomain
                        || response.response_code() == ResponseCode::NoError)
                {
                    return Ok(response);
                }

                // 3. Referral processing
                if response.name_servers().is_empty() {
                    tracing::warn!(
                        name = %name,
                        authoritative = response.authoritative(),
                        "[RECURSOR] Received response with no relevant answers, no authoritative SOA, and no delegation; invalid"
                    );
                    return Err(RecursorError::NoProgress);
                }

                let first_ns = response
                    .name_servers()
                    .iter()
                    .find(|r| r.record_type() == RecordType::NS);

                let Some(first_ns_rec) = first_ns else {
                    return Ok(response);
                };

                let delegation_owner = first_ns_rec.name().clone();

                let mut ns_names = Vec::new();
                for r in response.name_servers() {
                    if r.record_type() == RecordType::NS {
                        if r.name() != &delegation_owner {
                            tracing::warn!(
                                expected = %delegation_owner,
                                actual = %r.name(),
                                "[SECURITY] Inconsistent NS owners in referral; rejecting"
                            );
                            return Err(RecursorError::NoProgress);
                        }
                        if let RData::NS(ns) = r.data() {
                            ns_names.push(ns.0.clone());
                        }
                    }
                }

                if ns_names.is_empty() {
                    return Ok(response);
                }

                if last_zone.as_ref() == Some(&delegation_owner) {
                    return Err(RecursorError::NoProgress);
                }

                let is_child_of_target =
                    delegation_owner.zone_of(name) || &delegation_owner == name;
                let is_within_bailiwick = bailiwick.is_root()
                    || bailiwick.zone_of(&delegation_owner)
                    || bailiwick == delegation_owner;
                if !is_child_of_target || !is_within_bailiwick {
                    tracing::warn!(
                        delegation = %delegation_owner,
                        target = %name,
                        bailiwick = %bailiwick,
                        "[SECURITY] Out-of-bailiwick delegation rejected"
                    );
                    return Err(RecursorError::NoProgress);
                }

                let active_delegation = delegation_owner;

                let mut next_ips: Vec<IpAddr> = Vec::new();
                for add in response.additionals() {
                    if !ns_names.iter().any(|n| n == add.name()) {
                        continue;
                    }

                    let is_in_bailiwick = bailiwick.is_root()
                        || bailiwick.zone_of(add.name())
                        || &bailiwick == add.name()
                        || active_delegation.zone_of(add.name())
                        || &active_delegation == add.name();

                    if !is_in_bailiwick {
                        tracing::debug!(
                            ns = %add.name(),
                            delegation = %active_delegation,
                            "[SECURITY] Ignored out-of-bailiwick NS address in additionals (untrusted hint)"
                        );
                        continue;
                    }

                    match add.data() {
                        RData::A(a) => next_ips.push(IpAddr::V4(a.0)),
                        RData::AAAA(a) => next_ips.push(IpAddr::V6(a.0)),
                        _ => {}
                    }
                }

                let dropped_glue = next_ips.len();
                next_ips = filter_safe_ips(next_ips);
                if next_ips.len() != dropped_glue {
                    tracing::warn!(
                        zone = %active_delegation,
                        dropped = dropped_glue - next_ips.len(),
                        "[SECURITY] Dropped unsafe glue IP(s) in delegation"
                    );
                }

                if next_ips.is_empty() {
                    for ns_name in ns_names.iter().take(4) {
                        let key_ns = format!("ns:resolve:{}", ns_name.to_string().to_lowercase());
                        if !visited.contains(&key_ns) {
                            visited.insert(key_ns);

                            if let Ok(ns_resp) = self
                                .resolve_internal(ns_name, RecordType::A, depth + 1, visited)
                                .await
                            {
                                for ans in ns_resp.answers() {
                                    if let RData::A(a) = ans.data() {
                                        if is_safe_upstream_ip(IpAddr::V4(a.0)) {
                                            next_ips.push(IpAddr::V4(a.0));
                                        }
                                    }
                                }
                            }

                            if let Ok(ns_resp) = self
                                .resolve_internal(ns_name, RecordType::AAAA, depth + 1, visited)
                                .await
                            {
                                for ans in ns_resp.answers() {
                                    if let RData::AAAA(aaaa) = ans.data() {
                                        if is_safe_upstream_ip(IpAddr::V6(aaaa.0)) {
                                            next_ips.push(IpAddr::V6(aaaa.0));
                                        }
                                    }
                                }
                            }
                        }

                        if next_ips.len() >= 4 {
                            break;
                        }
                    }

                    let mut seen_ips = HashSet::new();
                    next_ips.retain(|ip| seen_ips.insert(*ip));
                }

                if next_ips.is_empty() {
                    return Err(RecursorError::GlueResolutionFailed);
                }

                let ttl = delegation_ttl(&response);
                self.delegation_cache.insert(
                    active_delegation.to_string().to_lowercase(),
                    DelegationEntry {
                        servers: next_ips.clone(),
                        expires_at: now_secs() + ttl,
                        source: DelegationSource::Dynamic,
                    },
                );

                bailiwick = active_delegation.clone();
                last_zone = Some(active_delegation);

                current_servers = next_ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, 53))
                    .collect();
            }

            Err(RecursorError::StepLimitExceeded)
        })
    }
}

pub fn calculate_min_ttl(msg: &Message) -> u32 {
    let mut min_ttl = u32::MAX;
    for r in msg.answers() {
        min_ttl = min_ttl.min(r.ttl());
    }
    for r in msg.name_servers() {
        min_ttl = min_ttl.min(r.ttl());
    }
    for r in msg.additionals() {
        min_ttl = min_ttl.min(r.ttl());
    }
    if min_ttl == u32::MAX {
        300
    } else {
        min_ttl.min(86400)
    }
}
