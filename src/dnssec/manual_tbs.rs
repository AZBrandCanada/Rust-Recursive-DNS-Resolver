// src/dnssec/manual_tbs.rs
//
// Manual DNSSEC TBS (To-Be-Signed) construction.
//
// hickory-proto 0.25.2's TBS::from_rrsig() is broken: it emits only
// the RRSIG RDATA prefix and silently drops the RRset records, so the
// resulting TBS is truncated (~26 bytes for uk.com instead of ~48).
// Every signature verification fails regardless of algorithm or key
// size.
//
// This module implements RFC 4034 §3.1.8.1 / RFC 4035 §5.3.2
// directly.
//
// Layout of the signed data:
//
//   RRSIG_RDATA_without_signature || RR(1) || RR(2) || ...
//
// Where RRSIG_RDATA_without_signature is:
//
//   type_covered   (u16, network byte order)
//   algorithm      (u8)
//   labels         (u8)
//   original_ttl   (u32, network byte order)
//   expiration     (u32, network byte order)
//   inception      (u32, network byte order)
//   key_tag        (u16, network byte order)
//   signer_name    (canonical, uncompressed wire format)
//
// And each RR(i) is:
//
//   owner_name     (canonical, uncompressed, wildcard-reconstructed)
//   type           (u16, network byte order)
//   class          (u16, network byte order)
//   original_ttl   (u32, network byte order, from the RRSIG)
//   rdata_length   (u16, network byte order)
//   rdata          (canonical wire format)
//
// Records are sorted in canonical order (RFC 4034 §6.3) before being
// appended.

use hickory_proto::dnssec::rdata::{DNSSECRData, RRSIG};
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::str::FromStr;

/// Build the DNSSEC TBS for an RRSIG over the given RRset.
///
/// Returns `None` if the RRSIG record cannot be parsed, the RRSIG
/// Labels field is invalid for the owner name, or any record in the
/// set does not match the RRSIG's type/class/name.
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

    // Count non-root labels. Name::iter() yields the root label as an
    // empty slice, so filter it out.
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

    let mut rrset: Vec<&Record> = records
        .iter()
        .filter(|r| {
            r.name() == &owner
                && r.record_type() == type_covered
                && r.dns_class() == rrsig_class
        })
        .collect();

    if rrset.is_empty() {
        tracing::debug!(
            owner = %owner,
            qtype = ?type_covered,
            "[manual_tbs] no records in RRset match RRSIG (name/type/class)"
        );
        return None;
    }

    // Canonical sort by RDATA bytes (RFC 4034 §6.3).
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
        encoder.set_canonical_names(true);

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
        step!(rrsig.signer_name().emit(&mut encoder));

        for record in &rrset {
            step!(canonical_owner.emit(&mut encoder));
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

fn canonical_rdata(record: &Record) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    {
        let mut encoder = BinEncoder::new(&mut buf);
        encoder.set_canonical_names(true);
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
