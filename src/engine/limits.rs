// src/engine/limits.rs
/// RFC 1035 §4.1.1: Minimum DNS message header size is 12 bytes.
pub const MIN_DNS_MSG_SIZE: usize = 12;

/// Operational ceiling on inbound UDP queries: 4096 bytes.
pub const MAX_UDP_QUERY_SIZE: usize = 4096;

/// Maximum theoretical UDP datagram payload size (65,535 bytes).
pub const MAX_UDP_USER_BUF: usize = 65535;

/// RFC 7766 §8: Maximum 16-bit frame size is 65,535 bytes.
pub const MAX_TCP_MSG_SIZE: usize = 65535;

/// RFC 8484 maximum payload size: 4096 bytes.
pub const MAX_DOH_PAYLOAD: usize = 4096;
