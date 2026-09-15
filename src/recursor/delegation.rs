// src/recursor/delegation.rs
use crate::cache::now_secs;
use dashmap::DashMap;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};
use std::net::IpAddr;

pub const MIN_DELEGATION_TTL: u64 = 300;
pub const MAX_DELEGATION_TTL: u64 = 172_800;

pub struct DelegationEntry {
    pub servers: Vec<IpAddr>,
    pub expires_at: u64,
}

pub fn delegation_ttl(msg: &Message) -> u64 {
    let mut min_ttl = u32::MAX;
    for r in msg.name_servers() {
        min_ttl = min_ttl.min(r.ttl());
    }
    for r in msg.additionals() {
        min_ttl = min_ttl.min(r.ttl());
    }
    if min_ttl == u32::MAX {
        MIN_DELEGATION_TTL
    } else {
        (min_ttl as u64).min(MAX_DELEGATION_TTL)
    }
}

pub fn purge_delegation(cache: &DashMap<String, DelegationEntry>, name: &Name, rtype: RecordType) {
    let mut current = if rtype == RecordType::DS {
        name.base_name()
    } else {
        name.clone()
    };
    loop {
        let key = current.to_string().to_lowercase();
        if cache.remove(&key).is_some() {
            break;
        }
        if current.is_root() {
            break;
        }
        current = current.base_name();
    }
}

pub fn find_cached_start(
    cache: &DashMap<String, DelegationEntry>,
    name: &Name,
    rtype: RecordType,
) -> Option<Vec<IpAddr>> {
    let now = now_secs();
    let mut current = if rtype == RecordType::DS {
        name.base_name()
    } else {
        name.clone()
    };
    loop {
        let key = current.to_string().to_lowercase();
        if let Some(entry) = cache.get(&key) {
            if entry.expires_at > now {
                return Some(entry.servers.clone());
            }
        }
        if current.is_root() {
            break;
        }
        current = current.base_name();
    }
    None
}
