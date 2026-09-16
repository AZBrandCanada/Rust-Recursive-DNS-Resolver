// src/dnssec/negative.rs
use super::chain::{build_trust_chain, ChainResult};
use super::crypto::{KeyTagExt, ValidationBudget};
use super::validator::{DnssecStatus, DnssecValidator};
use crate::recursor::RecursiveResolver;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY};
use hickory_proto::dnssec::Nsec3HashAlgorithm;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ring::digest;
use std::str::FromStr;

pub const MAX_NEGATIVE_RECORDS: usize = 8;
pub const MAX_NSEC3_ITERATIONS: u16 = 150;
pub const MAX_CLOSEST_ENCLOSER_STEPS: usize = 16;

pub async fn validate_negative(
    recursor: &RecursiveResolver,
    msg: &Message,
    qname: &Name,
    qtype: RecordType,
    budget: &mut ValidationBudget,
) -> DnssecStatus {
    let soa = msg
        .name_servers()
        .iter()
        .find(|r| matches!(r.data(), RData::SOA(_)));

    let zone = match soa {
        Some(r) => r.name().clone(),
        None => {
            tracing::debug!(
                qname = %qname,
                "[DNSSEC] Negative response has no SOA; treating as Unknown"
            );
            return DnssecStatus::InsecureUnknown;
        }
    };

    let final_target = msg
        .answers()
        .iter()
        .rfind(|r| r.record_type() == RecordType::CNAME)
        .and_then(|r| {
            if let RData::CNAME(cname) = r.data() {
                Some(cname.0.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| qname.clone());

    if !zone.zone_of(&final_target)
        && zone != final_target
        && !zone.zone_of(qname)
        && zone != *qname
    {
        tracing::warn!(
            zone = %zone,
            qname = %qname,
            final_target = %final_target,
            "[DNSSEC] Negative response SOA is not authoritative for target; Bogus"
        );
        return DnssecStatus::Bogus;
    }

    let keys = match build_trust_chain(recursor, &zone, budget).await {
        ChainResult::Trusted { keys: k, .. } => k,
        ChainResult::Unsigned { .. } => {
            tracing::debug!(
                zone = %zone,
                qname = %qname,
                "[DNSSEC] Negative: trust chain Unsigned; treating as Insecure"
            );
            return DnssecStatus::InsecureUnsigned;
        }
        ChainResult::Bogus => {
            tracing::warn!(
                zone = %zone,
                qname = %qname,
                "[DNSSEC] Negative: trust chain Bogus"
            );
            return DnssecStatus::Bogus;
        }
    };

    let authority: Vec<Record> = msg.name_servers().to_vec();

    if let Some(soa_rec) = soa {
        if !verify_negative_rrset(soa_rec, &authority, &keys, budget) {
            tracing::warn!(
                zone = %zone,
                qname = %qname,
                "[DNSSEC] Negative response SOA signature did not verify; Bogus"
            );
            return DnssecStatus::Bogus;
        }
    }

    let has_nsec3 = authority
        .iter()
        .any(|r| r.record_type() == RecordType::NSEC3);

    if has_nsec3 {
        return validate_nsec3(&keys, &final_target, qtype, &authority, budget);
    }

    let has_nsec = authority
        .iter()
        .any(|r| r.record_type() == RecordType::NSEC);

    if has_nsec {
        return validate_nsec(&keys, &final_target, qtype, &authority, budget);
    }

    tracing::warn!(
        zone = %zone,
        qname = %qname,
        "[DNSSEC] Signed zone negative response has no NSEC/NSEC3 proof; Bogus"
    );

    DnssecStatus::Bogus
}

pub fn verify_negative_rrset(
    rec: &Record,
    authority: &[Record],
    keys: &[DNSKEY],
    budget: &mut ValidationBudget,
) -> bool {
    let owner = rec.name().clone();
    let rtype = rec.record_type();

    let rrsig_records: Vec<Record> = authority
        .iter()
        .filter(|r| {
            if r.name() != &owner {
                return false;
            }

            matches!(
                r.data(),
                RData::DNSSEC(DNSSECRData::RRSIG(sig))
                    if sig.type_covered() == rtype
            )
        })
        .cloned()
        .collect();

    if rrsig_records.is_empty() {
        return false;
    }

    let full_rrset: Vec<Record> = authority
        .iter()
        .filter(|r| r.name() == &owner && r.record_type() == rtype)
        .cloned()
        .collect();

    if full_rrset.is_empty() {
        return false;
    }

    for rrsig_record in &rrsig_records {
        let sig = match rrsig_record.data() {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) if sig.type_covered() == rtype => sig,
            _ => continue,
        };

        for key in keys {
            if key.key_tag_matches(sig.key_tag()) {
                if !budget.can_check_sig() {
                    return false;
                }

                if DnssecValidator::verify_rrsig(sig, key, rrsig_record, &full_rrset) {
                    return true;
                }
            }
        }
    }

    false
}

pub fn validate_nsec(
    keys: &[DNSKEY],
    qname: &Name,
    qtype: RecordType,
    authority: &[Record],
    budget: &mut ValidationBudget,
) -> DnssecStatus {
    let nsec_records: Vec<&Record> = authority
        .iter()
        .filter(|r| r.record_type() == RecordType::NSEC)
        .take(MAX_NEGATIVE_RECORDS)
        .collect();

    if nsec_records.is_empty() {
        return DnssecStatus::Bogus;
    }

    for &nsec in &nsec_records {
        if !verify_negative_rrset(nsec, authority, keys, budget) {
            tracing::warn!(
                owner = %nsec.name(),
                "[DNSSEC] NSEC RRset signature did not verify; Bogus"
            );
            return DnssecStatus::Bogus;
        }
    }

    if let Some(status) = check_nsec_nodata(qname, qtype, &nsec_records) {
        return status;
    }

    let closest = match find_nsec_closest_encloser(qname, &nsec_records) {
        Some(c) => c,
        None => return DnssecStatus::Bogus,
    };

    if let Some(status) = check_nsec_wildcard_nodata(qname, qtype, &closest, &nsec_records) {
        return status;
    }

    if let Some(status) = check_nsec_nxdomain(qname, &closest, &nsec_records) {
        return status;
    }

    DnssecStatus::Bogus
}

pub fn validate_nsec3(
    keys: &[DNSKEY],
    qname: &Name,
    qtype: RecordType,
    authority: &[Record],
    budget: &mut ValidationBudget,
) -> DnssecStatus {
    let nsec3_records: Vec<&Record> = authority
        .iter()
        .filter(|r| r.record_type() == RecordType::NSEC3)
        .take(MAX_NEGATIVE_RECORDS)
        .collect();

    if nsec3_records.is_empty() {
        return DnssecStatus::Bogus;
    }

    let first = match nsec3_records[0].data() {
        RData::DNSSEC(DNSSECRData::NSEC3(n)) => n,
        _ => return DnssecStatus::Bogus,
    };

    let salt = first.salt().to_vec();
    let iterations = first.iterations();
    let algorithm = first.hash_algorithm();

    if algorithm != Nsec3HashAlgorithm::SHA1 {
        tracing::warn!("[DNSSEC] Unsupported NSEC3 hash algorithm; Unknown");
        return DnssecStatus::InsecureUnknown;
    }

    if iterations > MAX_NSEC3_ITERATIONS {
        tracing::warn!(
            iterations,
            "[DNSSEC] NSEC3 iterations exceed RFC 9276 cap; Unknown"
        );
        return DnssecStatus::InsecureUnknown;
    }

    for &rec in &nsec3_records {
        match rec.data() {
            RData::DNSSEC(DNSSECRData::NSEC3(n)) => {
                if n.hash_algorithm() != algorithm
                    || n.iterations() != iterations
                    || n.salt() != salt.as_slice()
                {
                    tracing::warn!("[DNSSEC] Inconsistent NSEC3 parameters in proof; Bogus");
                    return DnssecStatus::Bogus;
                }
            }
            _ => return DnssecStatus::Bogus,
        }
    }

    for &rec in &nsec3_records {
        if !verify_negative_rrset(rec, authority, keys, budget) {
            tracing::warn!(
                owner = %rec.name(),
                "[DNSSEC] NSEC3 RRset signature did not verify; Bogus"
            );
            return DnssecStatus::Bogus;
        }
    }

    if let Some(status) = check_nsec3_nodata(qname, qtype, &nsec3_records, &salt, iterations) {
        return status;
    }

    let mut closest =
        find_nsec3_closest_provable_encloser(qname, &nsec3_records, &salt, iterations);

    if closest.is_none() && qtype == RecordType::DS {
        closest = Some(qname.base_name());
    }

    let closest = match closest {
        Some(c) => c,
        None => return DnssecStatus::Bogus,
    };

    if closest == *qname {
        if qtype == RecordType::DS {
            return DnssecStatus::Secure;
        }

        return DnssecStatus::Bogus;
    }

    if let Some(status) =
        check_nsec3_wildcard_nodata(&closest, qtype, &nsec3_records, &salt, iterations)
    {
        return status;
    }

    if let Some(status) =
        check_nsec3_nxdomain(qname, &closest, qtype, &nsec3_records, &salt, iterations)
    {
        return status;
    }

    DnssecStatus::Bogus
}

pub fn find_nsec_closest_encloser(qname: &Name, nsec_records: &[&Record]) -> Option<Name> {
    let mut cur = if qname.is_root() {
        qname.clone()
    } else {
        qname.base_name()
    };

    let mut steps = 0usize;

    loop {
        steps += 1;

        if steps > MAX_CLOSEST_ENCLOSER_STEPS {
            return None;
        }

        if nsec_records.iter().any(|r| r.name() == &cur) {
            return Some(cur);
        }

        if cur.is_root() {
            break;
        }

        cur = cur.base_name();
    }

    None
}

pub fn check_nsec_nodata(
    qname: &Name,
    qtype: RecordType,
    nsec_records: &[&Record],
) -> Option<DnssecStatus> {
    for &rec in nsec_records {
        if rec.name() == qname {
            if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
                let has_type = nsec.type_bit_maps().any(|t| t == qtype);
                let has_cname = nsec.type_bit_maps().any(|t| t == RecordType::CNAME);
                let has_soa = nsec.type_bit_maps().any(|t| t == RecordType::SOA);
                let has_ns = nsec.type_bit_maps().any(|t| t == RecordType::NS);

                if qtype == RecordType::DS && has_soa {
                    return Some(DnssecStatus::Bogus);
                }

                if !has_type && !has_cname {
                    if qtype == RecordType::DS && has_ns {
                        tracing::debug!(
                            owner = %rec.name(),
                            "[DNSSEC] NSEC NODATA for DS with NS present; insecure delegation"
                        );
                        return Some(DnssecStatus::InsecureUnsigned);
                    }

                    return Some(DnssecStatus::Secure);
                }
            }
        }
    }

    None
}

pub fn check_nsec_wildcard_nodata(
    qname: &Name,
    qtype: RecordType,
    closest: &Name,
    nsec_records: &[&Record],
) -> Option<DnssecStatus> {
    let wildcard = wildcard_name(closest);

    let wildcard_nsec = nsec_records.iter().find(|&&r| r.name() == &wildcard)?;

    if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = wildcard_nsec.data() {
        let has_type = nsec.type_bit_maps().any(|t| t == qtype);
        let has_cname = nsec.type_bit_maps().any(|t| t == RecordType::CNAME);

        if has_type || has_cname {
            return None;
        }
    } else {
        return None;
    }

    let qname_covered = nsec_records.iter().any(|&rec| {
        if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
            nsec_covers(rec.name(), nsec.next_domain_name(), qname)
        } else {
            false
        }
    });

    if qname_covered {
        Some(DnssecStatus::Secure)
    } else {
        None
    }
}

pub fn check_nsec_nxdomain(
    qname: &Name,
    closest: &Name,
    nsec_records: &[&Record],
) -> Option<DnssecStatus> {
    let qname_covered = nsec_records.iter().any(|&rec| {
        if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
            nsec_covers(rec.name(), nsec.next_domain_name(), qname)
        } else {
            false
        }
    });

    if !qname_covered {
        return None;
    }

    let wildcard = wildcard_name(closest);

    let wildcard_covered = nsec_records.iter().any(|&rec| {
        if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = rec.data() {
            nsec_covers(rec.name(), nsec.next_domain_name(), &wildcard)
        } else {
            false
        }
    });

    if !wildcard_covered {
        return None;
    }

    Some(DnssecStatus::Secure)
}

pub fn find_nsec3_closest_provable_encloser(
    qname: &Name,
    nsec3_records: &[&Record],
    salt: &[u8],
    iterations: u16,
) -> Option<Name> {
    let mut cur = qname.clone();
    let mut steps = 0usize;

    loop {
        steps += 1;

        if steps > MAX_CLOSEST_ENCLOSER_STEPS {
            return None;
        }

        let h = nsec3_hash(&cur, salt, iterations);

        if nsec3_records
            .iter()
            .any(|&r| nsec3_owner_hash(r).as_deref() == Some(h.as_slice()))
        {
            return Some(cur);
        }

        if cur.is_root() {
            break;
        }

        cur = cur.base_name();
    }

    None
}

pub fn check_nsec3_nodata(
    qname: &Name,
    qtype: RecordType,
    nsec3_records: &[&Record],
    salt: &[u8],
    iterations: u16,
) -> Option<DnssecStatus> {
    let hashed_qname = nsec3_hash(qname, salt, iterations);

    for &rec in nsec3_records {
        if nsec3_owner_hash(rec).as_deref() == Some(hashed_qname.as_slice()) {
            if let RData::DNSSEC(DNSSECRData::NSEC3(n)) = rec.data() {
                let has_type = n.type_bit_maps().any(|t| t == qtype);
                let has_cname = n.type_bit_maps().any(|t| t == RecordType::CNAME);
                let has_soa = n.type_bit_maps().any(|t| t == RecordType::SOA);
                let has_ns = n.type_bit_maps().any(|t| t == RecordType::NS);

                if qtype == RecordType::DS && has_soa {
                    return Some(DnssecStatus::Bogus);
                }

                if !has_type && !has_cname {
                    if qtype == RecordType::DS && has_ns {
                        tracing::debug!(
                            owner = %rec.name(),
                            "[DNSSEC] NSEC3 NODATA for DS with NS present; insecure delegation"
                        );
                        return Some(DnssecStatus::InsecureUnsigned);
                    }

                    return Some(DnssecStatus::Secure);
                }
            }
        }
    }

    None
}

pub fn check_nsec3_wildcard_nodata(
    closest: &Name,
    qtype: RecordType,
    nsec3_records: &[&Record],
    salt: &[u8],
    iterations: u16,
) -> Option<DnssecStatus> {
    let wildcard = wildcard_name(closest);
    let hashed_wildcard = nsec3_hash(&wildcard, salt, iterations);

    let wildcard_rec = nsec3_records
        .iter()
        .find(|&&r| nsec3_owner_hash(r).as_deref() == Some(hashed_wildcard.as_slice()))?;

    if let RData::DNSSEC(DNSSECRData::NSEC3(n)) = wildcard_rec.data() {
        let has_type = n.type_bit_maps().any(|t| t == qtype);
        let has_cname = n.type_bit_maps().any(|t| t == RecordType::CNAME);

        if has_type || has_cname {
            return None;
        }
    } else {
        return None;
    }

    Some(DnssecStatus::Secure)
}

pub fn check_nsec3_nxdomain(
    qname: &Name,
    closest: &Name,
    qtype: RecordType,
    nsec3_records: &[&Record],
    salt: &[u8],
    iterations: u16,
) -> Option<DnssecStatus> {
    let mut next_closer = qname.clone();

    while next_closer.base_name() != *closest {
        let parent = next_closer.base_name();

        if parent == next_closer {
            return Some(DnssecStatus::Bogus);
        }

        next_closer = parent;
    }

    let hashed_next = nsec3_hash(&next_closer, salt, iterations);

    let covering_rec = nsec3_records
        .iter()
        .find(|&&r| nsec3_covers(r, &hashed_next))?;

    let is_opt_out = match covering_rec.data() {
        RData::DNSSEC(DNSSECRData::NSEC3(n)) => (n.flags() & 0x01) != 0,
        _ => false,
    };

    // RFC 5155 §8.7: when the NSEC3 covering the next-closer has the
    // Opt-Out flag set, the NXDOMAIN proof is not authenticated for
    // ANY qtype. The zone owner has explicitly declined to prove the
    // non-existence of unsigned delegations in the covered span, so
    // the answer cannot be considered Secure.
    //
    //   - For DS queries: the child delegation exists but is unsigned
    //     (insecure delegation) → return InsecureUnsigned.
    //   - For all other qtypes: the NXDOMAIN itself is not provably
    //     correct → return InsecureUnsigned so AD is not set.
    if is_opt_out {
        tracing::debug!(
            qname = %qname,
            qtype = ?qtype,
            covering_owner = %covering_rec.name(),
            "[DNSSEC] Opt-Out NSEC3 covers next-closer; treating as Insecure"
        );

        return Some(DnssecStatus::InsecureUnsigned);
    }

    let wildcard = wildcard_name(closest);
    let hashed_wildcard = nsec3_hash(&wildcard, salt, iterations);

    if !nsec3_records
        .iter()
        .any(|&r| nsec3_covers(r, &hashed_wildcard))
    {
        return Some(DnssecStatus::Bogus);
    }

    Some(DnssecStatus::Secure)
}

pub fn wildcard_name(closest: &Name) -> Name {
    if closest.is_root() {
        Name::from_str("*.").unwrap_or_else(|_| Name::root())
    } else {
        let base = closest.to_ascii();
        let base = base.trim_end_matches('.');

        Name::from_str(&format!("*.{}.", base)).unwrap_or_else(|_| Name::root())
    }
}

pub fn nsec_covers(owner: &Name, next: &Name, target: &Name) -> bool {
    let o = owner.to_lowercase();
    let n = next.to_lowercase();
    let t = target.to_lowercase();

    if o < n {
        o < t && t < n
    } else {
        o < t || t < n
    }
}

pub fn nsec3_owner_hash(rec: &Record) -> Option<Vec<u8>> {
    let s = rec.name().to_string();
    let first_label = s.trim_end_matches('.').split('.').next()?;
    let hash = base32hex_decode(first_label)?;

    if hash.len() != 20 {
        return None;
    }

    Some(hash)
}

pub fn nsec3_covers(rec: &Record, target_hash: &[u8]) -> bool {
    let owner_hash = match nsec3_owner_hash(rec) {
        Some(h) => h,
        None => return false,
    };

    let next_hash: Vec<u8> = match rec.data() {
        RData::DNSSEC(DNSSECRData::NSEC3(n)) => n.next_hashed_owner_name().to_vec(),
        _ => return false,
    };

    if owner_hash.as_slice() <= next_hash.as_slice() {
        owner_hash.as_slice() <= target_hash && target_hash < next_hash.as_slice()
    } else {
        owner_hash.as_slice() <= target_hash || target_hash < next_hash.as_slice()
    }
}

pub fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Vec<u8> {
    let mut wire = Vec::new();

    for label in name.iter() {
        let bytes: &[u8] = label;
        wire.push(bytes.len() as u8);
        wire.extend_from_slice(&bytes.to_ascii_lowercase());
    }

    wire.push(0);
    wire.extend_from_slice(salt);

    let mut hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &wire)
        .as_ref()
        .to_vec();

    for _ in 0..iterations {
        let mut d = hash.clone();
        d.extend_from_slice(salt);

        hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &d)
            .as_ref()
            .to_vec();
    }

    hash
}

pub fn base32hex_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

    let upper = s.to_ascii_uppercase();
    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::new();

    for c in upper.bytes() {
        let val = ALPHABET.iter().position(|&x| x == c)? as u64;

        bits = (bits << 5) | val;
        bit_count += 5;

        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }

    Some(out)
}
