// src/dnssec/manual_tbs.rs
//
// Manual DNSSEC TBS (To-Be-Signed) construction.
//
// Two hickory-proto 0.25.2 issues are corrected here:
//
//   1. TBS::from_rrsig() emits only the RRSIG RDATA prefix and drops
//      the RRset records entirely.
//
//   2. BinEncoder::set_canonical_names(true) does not lowercase
//      emitted labels. RFC 4034 §6.2 requires all names in the
//      canonical signed data to be lowercased, including names
//      embedded in RDATA (SOA mname/rname, CNAME, NS, MX, etc.).
//
// All Name emission is done via Name::iter(), which yields the raw
// label bytes with escape sequences already resolved. Do NOT use
// to_ascii().split('.') — that breaks on labels containing escaped
// dots (e.g. SOA rname fields like `disa\.tinker\.ie\.list\.dci`).

use hickory_proto::dnssec::rdata::{DNSSECRData, RRSIG};
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

/// Case-insensitive DNS name comparison (RFC 4343).
fn name_eq(a: &Name, b: &Name) -> bool {
    a.to_ascii().eq_ignore_ascii_case(&b.to_ascii())
}

pub fn build_tbs_manual(rrsig_record: &Record, records: &[Record]) -> Option<Vec<u8>> {
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
                    tracing::debug!(len = rdata.len(), "[manual_tbs] RDATA too long");
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
/// Uses `Name::iter()` to get the true label bytes. This is critical:
/// labels can contain escaped dots (e.g. SOA rname `disa\.tinker`)
/// which must be treated as single labels, not split on the dot.
fn emit_name_canonical(name: &Name, encoder: &mut BinEncoder) -> Result<(), std::fmt::Error> {
    for label in name.iter() {
        if label.is_empty() {
            // `Name::iter()` yields the root label as an empty slice.
            // The terminating 0x00 is written once after the loop.
            continue;
        }
        if label.len() > 63 {
            return Err(std::fmt::Error);
        }
        encoder
            .emit_u8(label.len() as u8)
            .map_err(|_| std::fmt::Error)?;
        for b in label {
            encoder
                .emit_u8(b.to_ascii_lowercase())
                .map_err(|_| std::fmt::Error)?;
        }
    }
    encoder.emit_u8(0).map_err(|_| std::fmt::Error)?;
    Ok(())
}

/// Canonicalize a record's RDATA per RFC 4034 §6.2.
///
/// Types with embedded domain names (SOA, CNAME, NS, MX, DNAME, PTR,
/// SRV, ...) must have those names lowercased too.
fn canonical_rdata(record: &Record) -> Option<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(64);

    match record.data() {
        RData::SOA(soa) => {
            let mut e = BinEncoder::new(&mut buf);
            emit_name_canonical(soa.mname(), &mut e).ok()?;
            emit_name_canonical(soa.rname(), &mut e).ok()?;
            e.emit_u32(soa.serial()).ok()?;
            e.emit_u32(soa.refresh() as u32).ok()?;
            e.emit_u32(soa.retry() as u32).ok()?;
            e.emit_u32(soa.expire() as u32).ok()?;
            e.emit_u32(soa.minimum()).ok()?;
        }
        RData::CNAME(cname) => {
            let mut e = BinEncoder::new(&mut buf);
            emit_name_canonical(&cname.0, &mut e).ok()?;
        }
        RData::NS(ns) => {
            let mut e = BinEncoder::new(&mut buf);
            emit_name_canonical(&ns.0, &mut e).ok()?;
        }
        RData::PTR(ptr) => {
            let mut e = BinEncoder::new(&mut buf);
            emit_name_canonical(&ptr.0, &mut e).ok()?;
        }
        RData::MX(mx) => {
            let mut e = BinEncoder::new(&mut buf);
            e.emit_u16(mx.preference()).ok()?;
            emit_name_canonical(mx.exchange(), &mut e).ok()?;
        }
        RData::SRV(srv) => {
            let mut e = BinEncoder::new(&mut buf);
            e.emit_u16(srv.priority()).ok()?;
            e.emit_u16(srv.weight()).ok()?;
            e.emit_u16(srv.port()).ok()?;
            emit_name_canonical(srv.target(), &mut e).ok()?;
        }
        _ => {
            // Types without embedded domain names (A, AAAA, DNSKEY, DS,
            // NSEC, NSEC3, TXT, ...).
            let mut e = BinEncoder::new(&mut buf);
            record.data().emit(&mut e).ok()?;
        }
    }

    Some(buf)
}

/// Reconstruct the name that was actually signed when the RRSIG is a
/// wildcard signature. Uses `Name::iter()` for the same reasons as
/// `emit_name_canonical`.
fn reconstruct_wildcard_name(owner: &Name, num_labels: u8) -> Option<Name> {
    let labels: Vec<&[u8]> = owner.iter().filter(|l| !l.is_empty()).collect();
    let owner_label_count = labels.len();

    if num_labels as usize >= owner_label_count {
        return Some(owner.clone());
    }

    let skip = owner_label_count - num_labels as usize;
    let tail = &labels[skip..];

    // Build "*.<tail>" using from_labels, which preserves labels
    // with embedded dots exactly (it does not re-parse the ASCII
    // presentation form).
    let mut parts: Vec<Vec<u8>> = Vec::with_capacity(tail.len() + 1);
    parts.push(b"*".to_vec());
    for label in tail {
        if label.len() > 63 {
            return None;
        }
        parts.push(label.to_vec());
    }
    parts.push(Vec::new()); // root label terminator

    Name::from_labels(parts).ok()
}
