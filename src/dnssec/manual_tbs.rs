// src/dnssec/manual_tbs.rs
//
// Manual DNSSEC TBS (To-Be-Signed) construction.
//
// Three hickory-proto 0.25.2 issues are corrected here:
//
//   1. TBS::from_rrsig() emits only the RRSIG RDATA prefix and drops
//      the RRset records entirely.
//
//   2. BinEncoder::set_canonical_names(true) does not cause
//      Name::emit() to lowercase the emitted labels, contrary to
//      RFC 4034 §6.2. Authoritative servers frequently send
//      uppercase owner names (CMU.EDU., NSEC3 hashes like
//      CK0POJMG...), which must be lowercased before hashing.
//
//   3. Name::eq in hickory-proto 0.25.2 is case-sensitive, contrary
//      to RFC 4343. Authoritative servers can return mixed-case
//      owner names within a single RRset, and a naive
//      `r.name() == owner` filter drops half the records.

use hickory_proto::dnssec::rdata::{DNSSECRData, RRSIG};
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::str::FromStr;

/// Case-insensitive DNS name comparison (RFC 4343).
fn name_eq(a: &Name, b: &Name) -> bool {
    a.to_ascii().eq_ignore_ascii_case(&b.to_ascii())
}

pub fn build_tbs_manual(
    rrsig_record: &Record,
    records: &[Record],
) -> Option<Vec<u8>> {
    let rrsig: &RRSIG = match rrsig_record.data() {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => s,
        _ => {
            tracing::debug!("[manual_tbs] record is not an RRSIG");
            return None;
        }
    };

    if records.is_empty() {
        tracing::debug!("[manual_tbs] empty RRset");
        return None;
    }

    let owner = rrsig_record.name().clone();
    let rrsig_class = rrsig_record.dns_class();
    let type_covered = rrsig.type_covered();
    let num_labels = rrsig.num_labels();

    let owner_label_count = owner.iter().filter(|l| !l.is_empty()).count() as u8;

    if num_labels > owner_label_count {
        tracing::debug!(
            owner = %owner,
            labels = num_labels,
            owner_labels = owner_label_count,
            "[manual_tbs] RRSIG Labels exceeds owner label count"
        );
        return None;
    }

    let canonical_owner = match reconstruct_wildcard_name(&owner, num_labels) {
        Some(n) => n,
        None => {
            tracing::debug!("[manual_tbs] wildcard reconstruction failed");
            return None;
        }
    };

    tracing::debug!(
        "[manual_tbs] owner={} signer={} type={:?} class={:?} labels={} input_records={}",
        owner,
        rrsig.signer_name(),
        type_covered,
        rrsig_class,
        num_labels,
        records.len(),
    );

    let mut rrset: Vec<&Record> = records
        .iter()
        .filter(|r| {
            name_eq(r.name(), &owner)
                && r.record_type() == type_covered
                && r.dns_class() == rrsig_class
        })
        .collect();

    tracing::debug!(
        "[manual_tbs] rrset after filter: {} of {}",
        rrset.len(),
        records.len(),
    );

    if rrset.is_empty() {
        for (i, r) in records.iter().enumerate() {
            tracing::debug!(
                "[manual_tbs]   miss[{}] name={} type={:?} class={:?}",
                i,
                r.name(),
                r.record_type(),
                r.dns_class(),
            );
        }
        return None;
    }

    let mut sortable: Vec<(Vec<u8>, &Record)> = Vec::with_capacity(rrset.len());
    for r in rrset.drain(..) {
        let bytes = match canonical_rdata(r) {
            Some(b) => b,
            None => {
                tracing::debug!(
                    owner = %r.name(),
                    "[manual_tbs] failed to canonicalize RDATA for sorting"
                );
                return None;
            }
        };
        sortable.push((bytes, r));
    }
    sortable.sort_by(|a, b| a.0.cmp(&b.0));
    let rrset: Vec<&Record> = sortable.into_iter().map(|(_, r)| r).collect();

    let mut buf: Vec<u8> = Vec::with_capacity(512);

    {
        let mut encoder = BinEncoder::new(&mut buf);

        macro_rules! step {
            ($expr:expr) => {
                match $expr {
                    Ok(()) => {}
                    Err(err) => {
                        tracing::debug!(
                            expr = stringify!($expr),
                            error = %err,
                            "[manual_tbs] encoder step failed"
                        );
                        return None;
                    }
                }
            };
        }

        step!(encoder.emit_u16(u16::from(type_covered)));
        step!(encoder.emit_u8(u8::from(rrsig.algorithm())));
        step!(encoder.emit_u8(num_labels));
        step!(encoder.emit_u32(rrsig.original_ttl()));
        step!(encoder.emit_u32(rrsig.sig_expiration().get()));
        step!(encoder.emit_u32(rrsig.sig_inception().get()));
        step!(encoder.emit_u16(rrsig.key_tag()));

        // Signer name in canonical (uncompressed, LOWERCASE) form.
        step!(emit_name_canonical(rrsig.signer_name(), &mut encoder));

        for record in &rrset {
            step!(emit_name_canonical(&canonical_owner, &mut encoder));
            step!(encoder.emit_u16(u16::from(type_covered)));
            step!(encoder.emit_u16(u16::from(rrsig_class)));
            step!(encoder.emit_u32(rrsig.original_ttl()));

            let rdata = match canonical_rdata(record) {
                Some(b) => b,
                None => {
                    tracing::debug!("[manual_tbs] canonical_rdata for emit failed");
                    return None;
                }
            };
            let rdata_len = match u16::try_from(rdata.len()) {
                Ok(n) => n,
                Err(_) => {
                    tracing::debug!(
                        len = rdata.len(),
                        "[manual_tbs] RDATA too long"
                    );
                    return None;
                }
            };
            step!(encoder.emit_u16(rdata_len));
            for b in &rdata {
                step!(encoder.emit_u8(*b));
            }
        }
    }

    Some(buf)
}

/// Emit a domain name in DNSSEC canonical wire format: uncompressed,
/// length-prefixed, and lowercased per RFC 4034 §6.2.
///
/// Returns `Ok(())` to integrate with the `step!` macro above.
/// Errors are surfaced as a synthetic `std::fmt::Error`, which the
/// macro stringifies and logs.
fn emit_name_canonical(
    name: &Name,
    encoder: &mut BinEncoder,
) -> Result<(), std::fmt::Error> {
    let ascii = name.to_ascii();
    let trimmed = ascii.trim_end_matches('.');

    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            let bytes = label.as_bytes();
            if bytes.len() > 63 {
                return Err(std::fmt::Error);
            }
            encoder.emit_u8(bytes.len() as u8).map_err(|_| std::fmt::Error)?;
            for b in bytes {
                encoder
                    .emit_u8(b.to_ascii_lowercase())
                    .map_err(|_| std::fmt::Error)?;
            }
        }
    }
    encoder.emit_u8(0).map_err(|_| std::fmt::Error)?;
    Ok(())
}

/// Encode a record's RDATA. Leaf types (A, AAAA, DNSKEY, DS, NSEC3)
/// contain no embedded domain names, so a plain emit is canonical.
fn canonical_rdata(record: &Record) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    {
        let mut encoder = BinEncoder::new(&mut buf);
        record.data().emit(&mut encoder).ok()?;
    }
    Some(buf)
}

fn reconstruct_wildcard_name(owner: &Name, num_labels: u8) -> Option<Name> {
    let owner_label_count = owner.iter().filter(|l| !l.is_empty()).count();
    if num_labels as usize >= owner_label_count {
        return Some(owner.clone());
    }

    let owner_ascii = owner.to_ascii();
    let trimmed = owner_ascii.trim_end_matches('.');
    let parts: Vec<&str> = trimmed.split('.').collect();
    let skip = parts.len().saturating_sub(num_labels as usize);
    let tail = parts[skip..].join(".");
    let wildcard = format!("*.{}.", tail);
    Name::from_str(&wildcard).ok()
}
