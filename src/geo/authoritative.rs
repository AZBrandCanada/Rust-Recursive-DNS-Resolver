// src/geo/authoritative.rs
//
// Authoritative A/AAAA answer for configured GSLB names.
//
// Returns up to `GEO_IP_FAILOVER_IP` A or AAAA records, ordered
// best-scoring-first. When GEO_IP_FAILOVER_IP=1 (the default) this is
// exactly one record, matching the strict-steering behavior. When set
// higher, clients that respect DNS ordering get strict steering, and
// clients that shuffle records get TCP-layer failover to the next
// healthy node without needing a DNS re-resolution.
//
// Unhealthy nodes are excluded from the response entirely. If no node
// is eligible for the requested family:
//   - A queries    → SERVFAIL
//   - AAAA queries → NODATA (NOERROR with empty answer)
//
// The GSLB decision is computed per-request and never enters the
// shared recursive cache.

use super::config::GeoNode;
use super::GeoState;
use crate::engine::response::make_servfail_wire;
use crate::engine::ProcessOutcome;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::IpAddr;

pub fn answer(
    geo: &GeoState,
    qname: &Name,
    qtype: RecordType,
    client_ip: IpAddr,
    req_msg: &Message,
    client_dnssec_ok: bool,
) -> ProcessOutcome {
    let client_location = geo.geoip.as_ref().and_then(|db| db.lookup(client_ip));
    let need_ipv6 = qtype == RecordType::AAAA;

    let scores = geo.router.score_all(client_location.as_ref(), need_ipv6);

    // A node is eligible for the requested family if it has an address
    // of the matching type. Unhealthy nodes are already filtered out
    // of `scores`.
    let family_matches = |n: &GeoNode| match qtype {
        RecordType::A => n.ipv4.is_some(),
        RecordType::AAAA => n.ipv6.is_some(),
        _ => false,
    };

    let take_n = geo.config.response_ip_count as usize;

    // Primary path: take up to `take_n` healthy nodes, best first.
    let mut selected: Vec<&GeoNode> = scores
        .iter()
        .filter_map(|s| geo.config.find_node(&s.node_name))
        .filter(|n| family_matches(n))
        .take(take_n)
        .collect();

    // Fallback 1: if no nodes passed the health filter, the health
    // signal itself is unreliable. Prefer to return all configured
    // nodes rather than SERVFAIL — clients can pick whichever
    // responds, which is better than no answer at all.
    if selected.is_empty() {
        tracing::warn!(
            qname = %qname,
            "[GEO_ROUTING] health filter excluded all nodes; returning all configured nodes as a fallback"
        );
        selected = geo
            .config
            .nodes
            .iter()
            .filter(|n| n.enabled)
            .filter(|n| family_matches(n))
            .take(take_n)
            .collect();
    }

    // Fallback 2: still nothing (no nodes match family, or none
    // enabled). Use the configured default if it matches the family.
    if selected.is_empty() {
        if let Some(default_name) = geo.config.default_node.as_deref() {
            if let Some(default_node) = geo.config.find_node(default_name) {
                if family_matches(default_node) {
                    selected.push(default_node);
                }
            }
        }
    }

    // No eligible node at all.
    if selected.is_empty() {
        if qtype == RecordType::AAAA {
            tracing::debug!(
                qname = %qname,
                client = %client_ip,
                "[GEO_ROUTING] no IPv6-capable node; returning NODATA"
            );
            return build_nodata(req_msg, qname, client_dnssec_ok);
        }
        tracing::warn!(
            qname = %qname,
            client = %client_ip,
            "[GEO_ROUTING] no eligible node and no default configured"
        );
        return ProcessOutcome::ServFail(make_servfail_wire(
            req_msg.id(),
            req_msg.queries().first(),
        ));
    }

    // Observability: one log line per decision. The top of the list
    // is the primary steering target.
    let region = client_location
        .as_ref()
        .and_then(|c| c.country.clone())
        .unwrap_or_else(|| "??".to_string());
    let top = scores.first();
    let returned_names: Vec<&str> = selected.iter().map(|n| n.name.as_str()).collect();
    let returned_joined = returned_names.join(",");

    tracing::info!(
        client_region = %region,
        selected_node = %selected[0].name,
        returned_nodes = %returned_joined,
        returned_count = selected.len(),
        qtype = %qtype,
        score = ?top.map(|s| s.score),
        distance_km = ?top.and_then(|s| s.distance_km),
        rtt_ms = ?top.and_then(|s| s.rtt_ms),
        health = ?top.map(|s| s.health),
        "[GEO_ROUTING] decision"
    );

    // Build response.
    let mut resp = Message::new();
    resp.set_id(req_msg.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_authoritative(true);
    resp.set_recursion_desired(req_msg.recursion_desired());
    resp.set_recursion_available(false);
    resp.set_checking_disabled(req_msg.checking_disabled());
    resp.set_response_code(ResponseCode::NoError);

    for q in req_msg.queries() {
        resp.add_query(q.clone());
    }

    let ttl = geo.config.routing_ttl;

    match qtype {
        RecordType::A => {
            for node in &selected {
                if let Some(v4) = node.ipv4 {
                    resp.add_answer(Record::from_rdata(qname.clone(), ttl, RData::A(A(v4))));
                }
            }
        }
        RecordType::AAAA => {
            for node in &selected {
                if let Some(v6) = node.ipv6 {
                    resp.add_answer(Record::from_rdata(
                        qname.clone(),
                        ttl,
                        RData::AAAA(AAAA(v6)),
                    ));
                }
            }
        }
        _ => {}
    }

    if req_msg.extensions().is_some() {
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(client_dnssec_ok);
        resp.set_edns(edns);
    }

    match resp.to_bytes() {
        Ok(wire) => ProcessOutcome::Success(wire),
        Err(e) => {
            tracing::warn!(error = %e, "[GEO_ROUTING] response encoding failed");
            ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), req_msg.queries().first()))
        }
    }
}

/// NODATA response: NOERROR, empty answer, echo the question.
fn build_nodata(req_msg: &Message, qname: &Name, client_dnssec_ok: bool) -> ProcessOutcome {
    let mut resp = Message::new();
    resp.set_id(req_msg.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_authoritative(true);
    resp.set_recursion_desired(req_msg.recursion_desired());
    resp.set_recursion_available(false);
    resp.set_checking_disabled(req_msg.checking_disabled());
    resp.set_response_code(ResponseCode::NoError);

    for q in req_msg.queries() {
        resp.add_query(q.clone());
    }

    if req_msg.extensions().is_some() {
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(client_dnssec_ok);
        resp.set_edns(edns);
    }

    let _ = qname;
    match resp.to_bytes() {
        Ok(wire) => ProcessOutcome::Success(wire),
        Err(_) => {
            ProcessOutcome::ServFail(make_servfail_wire(req_msg.id(), req_msg.queries().first()))
        }
    }
}
