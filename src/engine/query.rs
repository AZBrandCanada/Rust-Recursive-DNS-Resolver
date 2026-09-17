// src/engine/query.rs
use super::resolve::ProcessOutcome;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
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
    /// Client subnet from EDNS Client Subnet, if the upstream resolver
    /// provided one. Used for geo decisions in preference to the raw
    /// source IP, which for public resolvers is the resolver's own
    /// egress address, not the actual client.
    pub ecs_net: Option<IpAddr>,
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

    let (client_max_payload, client_dnssec_ok, ecs_net) = match req_msg.extensions().as_ref() {
        Some(e) => {
            let ecs = extract_ecs_client_net(e);
            (
                (e.max_payload() as usize).clamp(512, 1232),
                e.flags().dnssec_ok,
                ecs,
            )
        }
        None => (512, false, None),
    };

    let cache_key = canonical_cache_key(&qname, qtype);

    Ok(ParsedDnsQuery {
        req_msg,
        qname,
        qtype,
        client_max_payload,
        client_dnssec_ok,
        cache_key,
        ecs_net,
    })
}

/// Extract the client network address from EDNS Client Subnet (RFC 7871).
///
/// Returns the address with trailing bits zeroed according to the
/// source prefix length, so that the resulting IP can be used directly
/// as a GeoIP lookup key without leaking full client precision.
fn extract_ecs_client_net(edns: &hickory_proto::op::Edns) -> Option<IpAddr> {
    let opt = edns.option(EdnsCode::Subnet)?;
    match opt {
        EdnsOption::Subnet(subnet) => {
            let addr = subnet.addr();
            let prefix = subnet.source_prefix();
            mask_addr(addr, prefix)
        }
        _ => None,
    }
}

fn mask_addr(addr: IpAddr, prefix: u8) -> Option<IpAddr> {
    match addr {
        IpAddr::V4(v4) => {
            if prefix == 0 || prefix > 32 {
                // RFC 7871 §7.1.2: source prefix 0 means no useful info.
                return None;
            }
            let bits = u32::from(v4);
            let mask = if prefix == 32 {
                u32::MAX
            } else {
                !((1u32 << (32 - prefix)) - 1)
            };
            Some(IpAddr::V4(std::net::Ipv4Addr::from(bits & mask)))
        }
        IpAddr::V6(v6) => {
            if prefix == 0 || prefix > 128 {
                return None;
            }
            let bits = u128::from(v6);
            let mask = if prefix == 128 {
                u128::MAX
            } else {
                !((1u128 << (128 - prefix)) - 1)
            };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(bits & mask)))
        }
    }
}

pub fn canonical_cache_key(qname: &Name, qtype: RecordType) -> String {
    format!("{}:{}:IN", qname.to_ascii().to_lowercase(), qtype)
}
