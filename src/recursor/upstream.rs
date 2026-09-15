// src/recursor/upstream.rs
use super::RecursorError;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable};
use rand::seq::SliceRandom;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::timeout;

pub const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",     // a.root-servers.net
    "199.9.14.201",   // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33",   // m.root-servers.net
];

pub const QUERY_TIMEOUT: Duration = Duration::from_millis(2000);
pub const TCP_TIMEOUT: Duration = Duration::from_millis(2500);

pub fn decode_response(buf: &[u8]) -> Result<Message, hickory_proto::ProtoError> {
    let mut decoder = BinDecoder::new(buf);
    match Message::read(&mut decoder) {
        Ok(msg) => Ok(msg),
        Err(e) => {
            if buf.len() >= 12 {
                let arcount = u16::from_be_bytes([buf[10], buf[11]]);
                if arcount > 0 {
                    let mut sanitized = buf.to_vec();
                    sanitized[10] = 0;
                    sanitized[11] = 0;
                    let mut second_decoder = BinDecoder::new(&sanitized);
                    if let Ok(salvaged) = Message::read(&mut second_decoder) {
                        tracing::debug!(
                            arcount,
                            "[RECURSOR] Salvaged DNS response by ignoring malformed Additional section"
                        );
                        return Ok(salvaged);
                    }
                }
            }
            Err(e)
        }
    }
}

pub fn is_safe_upstream_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
            {
                return false;
            }
            let o = v4.octets();
            if o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000 {
                return false;
            }
            if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                return false;
            }
            if o[0] == 0 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let seg0 = v6.segments()[0];
            if (seg0 & 0xfe00) == 0xfc00 {
                return false;
            }
            if (seg0 & 0xffc0) == 0xfe80 {
                return false;
            }
            let seg = v6.segments();
            if seg[0] == 0
                && seg[1] == 0
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0xffff
            {
                let mapped = Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                return is_safe_upstream_ip(IpAddr::V4(mapped));
            }
            true
        }
    }
}

pub fn filter_safe_ips(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    ips.into_iter()
        .filter(|ip| is_safe_upstream_ip(*ip))
        .collect()
}

pub async fn query_servers_with_fallback(
    servers: &[SocketAddr],
    name: &Name,
    rtype: RecordType,
) -> Option<Message> {
    if servers.is_empty() {
        return None;
    }

    let mut v4: Vec<SocketAddr> = servers.iter().filter(|s| s.is_ipv4()).cloned().collect();
    let mut v6: Vec<SocketAddr> = servers.iter().filter(|s| s.is_ipv6()).cloned().collect();
    {
        v4.shuffle(&mut rand::thread_rng());
        v6.shuffle(&mut rand::thread_rng());
    }

    let mut prioritized_servers = v4;
    prioritized_servers.extend(v6);

    for chunk in prioritized_servers.chunks(3) {
        let mut set = JoinSet::new();
        for &addr in chunk {
            let name = name.clone();
            set.spawn(async move { query_socket(addr, &name, rtype).await });
        }

        while let Some(joined) = set.join_next().await {
            if let Ok(Ok(msg)) = joined {
                match msg.response_code() {
                    ResponseCode::NoError | ResponseCode::NXDomain => {
                        return Some(msg);
                    }
                    _ => {}
                }
            }
        }
    }

    None
}

pub async fn query_socket(
    addr: SocketAddr,
    name: &Name,
    rtype: RecordType,
) -> Result<Message, RecursorError> {
    if !is_safe_upstream_ip(addr.ip()) {
        tracing::warn!(ip = %addr.ip(), "[SECURITY] Refused to query unsafe upstream IP");
        return Err(RecursorError::AllNameserversFailed);
    }

    let txid: u16 = rand::thread_rng().gen();

    let mut query_msg = Message::new();
    query_msg.set_id(txid);
    query_msg.set_message_type(MessageType::Query);
    query_msg.set_op_code(OpCode::Query);
    query_msg.set_recursion_desired(false);
    query_msg.set_checking_disabled(true);

    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(true);
    query_msg.set_edns(edns);

    let mut query = Query::new();
    query.set_name(name.clone());
    query.set_query_type(rtype);
    query.set_query_class(DNSClass::IN);
    query_msg.add_query(query.clone());

    let req_bytes = query_msg.to_bytes()?;

    let bind_addr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(ip = %addr.ip(), error = %e, "[RECURSOR] Failed to bind local socket for upstream query");
            return Err(RecursorError::AllNameserversFailed);
        }
    };

    if let Err(e) = socket.connect(addr).await {
        tracing::debug!(ip = %addr.ip(), error = %e, "[RECURSOR] Failed to connect to upstream IP (e.g. network unreachable)");
        return Err(RecursorError::AllNameserversFailed);
    }

    socket.send(&req_bytes).await?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
        .await
        .map_err(|_| RecursorError::AllNameserversFailed)??;

    let response = match decode_response(&buf[..n]) {
        Ok(resp) if resp.response_code() != ResponseCode::FormErr => resp,
        Ok(resp) => {
            tracing::debug!(
                ip = %addr.ip(),
                name = %name,
                rtype = ?rtype,
                rcode = ?resp.response_code(),
                "[RECURSOR] Upstream returned FORMERR to EDNS/DNSSEC query; retrying over TCP with EDNS"
            );

            let mut stream = timeout(TCP_TIMEOUT, TcpStream::connect(addr))
                .await
                .map_err(|_| RecursorError::AllNameserversFailed)?
                .map_err(|_| RecursorError::AllNameserversFailed)?;

            let len = (req_bytes.len() as u16).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&req_bytes).await?;

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;

            let resp_len = u16::from_be_bytes(len_buf) as usize;
            if !(12..=65535).contains(&resp_len) {
                return Err(RecursorError::Proto(hickory_proto::ProtoError::from(
                    "Invalid TCP frame length",
                )));
            }

            let mut tcp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut tcp_buf).await?;

            decode_response(&tcp_buf)?
        }
        Err(e) => {
            tracing::debug!(
                ip = %addr.ip(),
                name = %name,
                rtype = ?rtype,
                error = %e,
                "[RECURSOR] Failed to decode EDNS/DNSSEC response; retrying over TCP with EDNS"
            );

            let mut stream = timeout(TCP_TIMEOUT, TcpStream::connect(addr))
                .await
                .map_err(|_| RecursorError::AllNameserversFailed)?
                .map_err(|_| RecursorError::AllNameserversFailed)?;

            let len = (req_bytes.len() as u16).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&req_bytes).await?;

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;

            let resp_len = u16::from_be_bytes(len_buf) as usize;
            if !(12..=65535).contains(&resp_len) {
                return Err(RecursorError::Proto(hickory_proto::ProtoError::from(
                    "Invalid TCP frame length",
                )));
            }

            let mut tcp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut tcp_buf).await?;

            decode_response(&tcp_buf)?
        }
    };

    if !response_matches(&response, txid, name, rtype) {
        return Err(RecursorError::AllNameserversFailed);
    }

    if response.truncated() {
        let tcp_response = timeout(TCP_TIMEOUT, async {
            let mut stream = TcpStream::connect(addr).await?;
            let tcp_query_bytes = req_bytes.clone();

            let len = (tcp_query_bytes.len() as u16).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&tcp_query_bytes).await?;

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            if !(12..=65535).contains(&resp_len) {
                return Err(RecursorError::Proto(hickory_proto::ProtoError::from(
                    "Invalid TCP frame length",
                )));
            }

            let mut tcp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut tcp_buf).await?;

            match decode_response(&tcp_buf) {
                Ok(tcp_msg) => Ok(tcp_msg),
                Err(e) => {
                    tracing::debug!(
                        ip = %addr.ip(),
                        name = %name,
                        rtype = ?rtype,
                        error = %e,
                        "[RECURSOR] Failed to decode TCP response with EDNS/DNSSEC query"
                    );
                    Err(RecursorError::AllNameserversFailed)
                }
            }
        })
        .await
        .map_err(|_| RecursorError::AllNameserversFailed)?
        .map_err(|_: RecursorError| RecursorError::AllNameserversFailed)?;

        if !response_matches(&tcp_response, txid, name, rtype) {
            return Err(RecursorError::AllNameserversFailed);
        }
        return Ok(tcp_response);
    }

    Ok(response)
}

pub fn response_matches(response: &Message, txid: u16, sent_name: &Name, rtype: RecordType) -> bool {
    if response.id() != txid || response.message_type() != MessageType::Response {
        return false;
    }
    if response.op_code() != OpCode::Query {
        return false;
    }
    if response.queries().len() != 1 {
        return false;
    }
    let q = &response.queries()[0];
    if q.query_type() != rtype || q.query_class() != DNSClass::IN {
        return false;
    }

    q.name() == sent_name
}
