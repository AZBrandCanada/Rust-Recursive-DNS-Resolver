// src/engine/query.rs
use super::resolve::ProcessOutcome;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use std::net::IpAddr;

pub struct ParsedDnsQuery {
    pub req_msg: Message,
    pub qname: Name,
    pub qtype: RecordType,
    pub client_max_payload: usize,
    pub client_dnssec_ok: bool,
    pub cache_key: String,
}

pub fn parse_and_validate_query(
    req_wire: &[u8],
    protocol: &'static str,
    client_ip: IpAddr,
) -> Result<ParsedDnsQuery, ProcessOutcome> {
    let mut decoder = BinDecoder::new(req_wire);
    let req_msg = match Message::read(&mut decoder) {
        Ok(m) => m,
        Err(_) => return Err(ProcessOutcome::Malformed),
    };

    // RFC 1035 §4.1.2 & RFC 8906 §3.2: Reject messages not containing exactly one query.
    if req_msg.queries().len() != 1 {
        tracing::debug!(
            protocol,
            client = %client_ip,
            query_count = req_msg.queries().len(),
            "[DNS] Request does not contain exactly one question; rejecting as Malformed"
        );
        return Err(ProcessOutcome::Malformed);
    }

    let query = &req_msg.queries()[0];
    let qname = query.name().clone();
    let qtype = query.query_type();

    let (client_max_payload, client_dnssec_ok) = match req_msg.extensions().as_ref() {
        Some(e) => (
            (e.max_payload() as usize).clamp(512, 1232),
            e.flags().dnssec_ok,
        ),
        None => (512, false),
    };

    let cache_key = canonical_cache_key(&qname, qtype);

    Ok(ParsedDnsQuery {
        req_msg,
        qname,
        qtype,
        client_max_payload,
        client_dnssec_ok,
        cache_key,
    })
}

pub fn canonical_cache_key(qname: &Name, qtype: RecordType) -> String {
    format!("{}:{}:IN", qname.to_ascii().to_lowercase(), qtype)
}
