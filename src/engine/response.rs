// src/engine/response.rs
use crate::cache::{CacheFreshness, STALE_SERVE_TTL};
use crate::dnssec::DnssecStatus;
use crate::recursor::calculate_min_ttl;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::{Edns, Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::BinEncodable;

pub fn is_cacheable(msg: &Message) -> bool {
    matches!(
        msg.response_code(),
        ResponseCode::NoError | ResponseCode::NXDomain
    )
}

pub fn is_cacheable_dnssec(status: DnssecStatus) -> bool {
    matches!(
        status,
        DnssecStatus::Secure | DnssecStatus::InsecureUnsigned
    )
}

pub fn is_dnssec_record(rtype: RecordType) -> bool {
    matches!(
        rtype,
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
    )
}

/// RFC 4035 §5.3.3: Calculates the effective cache TTL: min(DNS RR TTL, remaining RRSIG validity).
pub fn calculate_cache_ttl(msg: &Message, status: DnssecStatus, now: u64) -> u32 {
    let mut ttl = calculate_min_ttl(msg);
    if status == DnssecStatus::Secure {
        let now32 = (now & 0xFFFF_FFFF) as u32;
        let mut min_rrsig_validity = u32::MAX;

        for r in msg.answers().iter().chain(msg.name_servers().iter()) {
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = r.data() {
                let exp = sig.sig_expiration().get();
                let diff = exp.wrapping_sub(now32) as i32;
                if diff > 0 {
                    min_rrsig_validity = min_rrsig_validity.min(diff as u32);
                } else {
                    return 0;
                }
            }
        }

        if min_rrsig_validity != u32::MAX {
            ttl = ttl.min(min_rrsig_validity);
        }
    }
    ttl
}

/// Constructs a client-tailored DNS response from a canonical validated message.
#[allow(clippy::too_many_arguments)]
pub fn construct_client_response(
    base_msg: &Message,
    qtype: RecordType,
    dnssec_status: DnssecStatus,
    freshness: CacheFreshness,
    cached_at: u64,
    req_msg: &Message,
    client_max_payload: usize,
    client_dnssec_ok: bool,
    now: u64,
) -> Option<Vec<u8>> {
    let mut client_resp = Message::new();

    // 1. Transaction ID and base header flags
    client_resp.set_id(req_msg.id());
    client_resp.set_message_type(MessageType::Response);
    client_resp.set_op_code(req_msg.op_code());
    client_resp.set_authoritative(false);
    client_resp.set_truncated(false);
    client_resp.set_recursion_available(true);
    client_resp.set_recursion_desired(req_msg.recursion_desired());
    client_resp.set_checking_disabled(req_msg.checking_disabled());
    client_resp.set_response_code(base_msg.response_code());

    for q in req_msg.queries() {
        client_resp.add_query(q.clone());
    }

    // 2. AD bit determination (RFC 4035 §3.2.2/3, RFC 6840 §5.7/8, RFC 8767 §6)
    let client_wants_ad = client_dnssec_ok || req_msg.authentic_data();
    let client_cd = req_msg.checking_disabled();

    let ad = dnssec_status == DnssecStatus::Secure
        && freshness == CacheFreshness::Fresh
        && client_wants_ad
        && !client_cd;

    client_resp.set_authentic_data(ad);

    // 3. TTL aging and DO=0 presentation filtering
    let age = now.saturating_sub(cached_at) as u32;

    let compute_ttl = |orig_ttl: u32| -> u32 {
        match freshness {
            CacheFreshness::Fresh => orig_ttl.saturating_sub(age),
            CacheFreshness::Stale => STALE_SERVE_TTL,
            CacheFreshness::Expired => 0,
        }
    };

    for r in base_msg.answers() {
        if !client_dnssec_ok && is_dnssec_record(r.record_type()) && r.record_type() != qtype {
            continue;
        }
        let mut rec = r.clone();
        rec.set_ttl(compute_ttl(rec.ttl()));
        client_resp.add_answer(rec);
    }

    for r in base_msg.name_servers() {
        if !client_dnssec_ok && is_dnssec_record(r.record_type()) && r.record_type() != qtype {
            continue;
        }
        let mut rec = r.clone();
        rec.set_ttl(compute_ttl(rec.ttl()));
        client_resp.add_name_server(rec);
    }

    for r in base_msg.additionals() {
        if r.record_type() == RecordType::OPT {
            continue;
        }
        if !client_dnssec_ok && is_dnssec_record(r.record_type()) && r.record_type() != qtype {
            continue;
        }
        let mut rec = r.clone();
        rec.set_ttl(compute_ttl(rec.ttl()));
        client_resp.add_additional(rec);
    }

    // 4. EDNS0 (OPT) handling (RFC 6891 §6.1.1)
    if req_msg.extensions().is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(client_max_payload as u16);
        edns.set_dnssec_ok(client_dnssec_ok);
        edns.set_version(0);
        client_resp.set_edns(edns);
    }

    client_resp.to_bytes().ok()
}

pub fn make_truncated_wire(id: u16, query: Option<&Query>) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_truncated(true);
    msg.set_recursion_available(true);
    msg.set_authoritative(false);
    if let Some(q) = query {
        msg.add_query(q.clone());
    }
    msg.to_bytes().unwrap_or_default()
}

pub fn make_servfail_wire(id: u16, query: Option<&Query>) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_response_code(ResponseCode::ServFail);
    msg.set_recursion_available(true);
    msg.set_authoritative(false);
    if let Some(q) = query {
        msg.add_query(q.clone());
    }
    msg.to_bytes().unwrap_or_default()
}
