// src/geo/authoritative.rs
//
// Authoritative A/AAAA answer for configured GSLB names.
//
// The selected node's single IPv4 (or IPv6) address is returned. No
// round-robin, no client-side reordering ambiguity — the steering is
// enforced by returning exactly one address.
//
// Unsupported types return NODATA (NOERROR with empty answer).
// On any internal failure, SERVFAIL is returned rather than falling
// through to the recursive resolver, because this name is not meant
// to be resolved recursively.

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

    // Pick top, or fall back to the configured default node.
    let selected_name = match scores.first() {
        Some(s) => s.node_name.clone(),
        None => match geo.config.default_node.clone() {
            Some(d) => d,
            None => {
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
        },
    };

    let node = match geo.config.find_node(&selected_name) {
        Some(n) => n,
        None => {
            tracing::warn!(node = %selected_name, "[GEO_ROUTING] selected node not found");
            return ProcessOutcome::ServFail(make_servfail_wire(
                req_msg.id(),
                req_msg.queries().first(),
            ));
        }
    };

    // Observability: single structured log per decision.
    let region = client_location
        .as_ref()
        .and_then(|c| c.country.clone())
        .unwrap_or_else(|| "??".to_string());
    let top = scores.first();
    tracing::info!(
        client_region = %region,
        selected_node = %node.name,
        qtype = %qtype,
        score = ?top.map(|s| s.score),
        distance_km = ?top.and_then(|s| s.distance_km),
        rtt_ms = ?top.and_then(|s| s.rtt_ms),
        health = ?top.map(|s| s.health),
        "[GEO_ROUTING] decision"
    );

    // Build response
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
            if let Some(v4) = node.ipv4 {
                resp.add_answer(Record::from_rdata(qname.clone(), ttl, RData::A(A(v4))));
            }
        }
        RecordType::AAAA => {
            if let Some(v6) = node.ipv6 {
                resp.add_answer(Record::from_rdata(qname.clone(), ttl, RData::AAAA(AAAA(v6))));
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
