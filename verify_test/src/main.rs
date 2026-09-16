// verify_test/src/main.rs
//
// Standalone verification test for the DNSSEC algorithm-7 issue.
//
// Fetches A + RRSIG + DNSKEY over DoH, builds the TBS manually
// (RFC 4034 §3.1.8.1), and tries both ring and the pure-Rust rsa
// crate.
//
// Key detail: the rrset filter uses the RRSIG's owner name (which is
// an absolute FQDN taken from the response) rather than the query
// name (which Name::from_str produces as a relative name, and which
// will not compare equal to an FQDN).

use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::dnssec::PublicKey;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use ring::signature;
use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey as RsaVK};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use sha1::Sha1;
use sha2::Sha256;
use std::str::FromStr;

const DOH: &str = "https://dns.google/dns-query";

async fn fetch(qname: &Name, qtype: RecordType) -> Message {
    let mut msg = Message::new();
    msg.set_id(0x1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(qname.clone(), qtype));

    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(4096);
    edns.set_dnssec_ok(true);
    let _ = msg.extensions_mut().insert(edns);

    let mut buf = Vec::new();
    msg.emit(&mut BinEncoder::new(&mut buf)).unwrap();

    let resp = reqwest::Client::new()
        .post(DOH)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(buf)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();

    Message::from_bytes(&resp).unwrap()
}

fn parse_rsa_pubkey(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    if bytes.is_empty() {
        return None;
    }
    let (exp_len, rest) = if bytes[0] == 0 {
        if bytes.len() < 3 {
            return None;
        }
        let len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        (len, &bytes[3..])
    } else {
        (bytes[0] as usize, &bytes[1..])
    };
    if exp_len == 0 || rest.len() < exp_len {
        return None;
    }
    let (e, m) = rest.split_at(exp_len);
    Some((e, m))
}

fn ring_sha1(e: &[u8], n: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    signature::RsaPublicKeyComponents { n, e }
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            msg,
            sig,
        )
        .is_ok()
}

fn ring_sha256(e: &[u8], n: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    signature::RsaPublicKeyComponents { n, e }
        .verify(&signature::RSA_PKCS1_2048_8192_SHA256, msg, sig)
        .is_ok()
}

fn rsa_crate_sha1(e: &[u8], n: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let key = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
        .map_err(|err| format!("RsaPublicKey::new: {err}"))?;
    let vk = RsaVK::<Sha1>::new(key);
    let sig_obj = RsaSig::try_from(sig).map_err(|err| format!("sig parse: {err}"))?;
    vk.verify(msg, &sig_obj).map_err(|err| format!("verify: {err}"))
}

fn rsa_crate_sha256(e: &[u8], n: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let key = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
        .map_err(|err| format!("RsaPublicKey::new: {err}"))?;
    let vk = RsaVK::<Sha256>::new(key);
    let sig_obj = RsaSig::try_from(sig).map_err(|err| format!("sig parse: {err}"))?;
    vk.verify(msg, &sig_obj).map_err(|err| format!("verify: {err}"))
}

async fn probe(domain: &str) {
    let name = Name::from_str(domain).unwrap();
    println!("\n===== {domain} A =====");

    let ans_msg = fetch(&name, RecordType::A).await;
    let key_msg = fetch(&name, RecordType::DNSKEY).await;

    // Dump every record in the answer section so we can see exactly
    // what Google returned.
    for (i, r) in ans_msg.answers().iter().enumerate() {
        println!(
            "  ans[{}]: name={} type={:?} class={:?} ttl={}",
            i, r.name(), r.record_type(), r.dns_class(), r.ttl(),
        );
    }

    let rrsig_rec = ans_msg
        .answers()
        .iter()
        .find(|r| matches!(r.data(), RData::DNSSEC(DNSSECRData::RRSIG(_))))
        .cloned();

    let Some(rrsig_rec) = rrsig_rec else {
        println!("no RRSIG in A response");
        return;
    };

    let rrsig: RRSIG = match rrsig_rec.data() {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => s.clone(),
        _ => unreachable!(),
    };

    let rtype = rrsig.type_covered();
    let owner = rrsig_rec.name().clone();

    println!(
        "RRSIG: alg={} tag={} labels={} sig_len={} owner={} class={:?} type_covered={:?}",
        u8::from(rrsig.algorithm()),
        rrsig.key_tag(),
        rrsig.num_labels(),
        rrsig.sig().len(),
        owner,
        rrsig_rec.dns_class(),
        rtype,
    );

    // Use the RRSIG's owner name (an FQDN from the response) for the
    // filter. The query name from Name::from_str is a relative name
    // and would not compare equal to a response record's FQDN name.
    let rrset: Vec<Record> = ans_msg
        .answers()
        .iter()
        .filter(|r| r.name() == &owner && r.record_type() == rtype)
        .cloned()
        .collect();

    println!("rrset records for owner/type: {}", rrset.len());

    let tbs = match manual_tbs(&rrsig_rec, &rrset) {
        Some(t) => t,
        None => {
            println!("manual TBS construction failed (see [tbs] lines above)");
            return;
        }
    };

    println!("TBS length: {} bytes", tbs.len());

    let keys: Vec<DNSKEY> = key_msg
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
            _ => None,
        })
        .collect();

    for k in &keys {
        let ktag = k.calculate_key_tag().unwrap_or(0);
        if ktag != rrsig.key_tag() {
            continue;
        }
        let kalg = u8::from(k.public_key().algorithm());
        let pub_bytes = k.public_key().public_bytes();
        println!(
            "matching DNSKEY: alg={} tag={} flags={} pubkey_bytes={}",
            kalg, ktag, k.flags(), pub_bytes.len(),
        );

        let Some((e, n)) = parse_rsa_pubkey(pub_bytes) else {
            println!("  parse_rsa_pubkey failed");
            continue;
        };
        println!("  RSA modulus = {} bits", n.len() * 8);

        match kalg {
            5 | 7 => {
                let r_ring = ring_sha1(e, n, &tbs, rrsig.sig());
                let r_rsa = rsa_crate_sha1(e, n, &tbs, rrsig.sig());
                println!("  ring RSA/SHA1   : {r_ring}");
                println!("  rsa  RSA/SHA1   : {r_rsa:?}");
            }
            8 => {
                let r_ring = ring_sha256(e, n, &tbs, rrsig.sig());
                let r_rsa = rsa_crate_sha256(e, n, &tbs, rrsig.sig());
                println!("  ring RSA/SHA256 : {r_ring}");
                println!("  rsa  RSA/SHA256 : {r_rsa:?}");
            }
            _ => println!("  unsupported alg for this test"),
        }
    }
}

#[tokio::main]
async fn main() {
    for d in &["uk.com", "eu.com", "us.com", "co.com", "cmu.edu", "uk.net"] {
        probe(d).await;
    }
}

// ─── Manual DNSSEC TBS (RFC 4034 §3.1.8.1) ───────────────────────────────────

fn manual_tbs(rrsig_record: &Record, records: &[Record]) -> Option<Vec<u8>> {
    let rrsig: &RRSIG = match rrsig_record.data() {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => s,
        _ => {
            eprintln!("[tbs] rrsig_record.data() is not RRSIG");
            return None;
        }
    };

    if records.is_empty() {
        eprintln!("[tbs] records is empty");
        return None;
    }

    let owner = rrsig_record.name().clone();
    let rrsig_class = rrsig_record.dns_class();
    let type_covered = rrsig.type_covered();
    let num_labels = rrsig.num_labels();

    let owner_label_count = owner.iter().filter(|l| !l.is_empty()).count() as u8;

    eprintln!(
        "[tbs] owner={} class={:?} type_covered={:?} num_labels={} owner_label_count={}",
        owner, rrsig_class, type_covered, num_labels, owner_label_count,
    );

    if num_labels > owner_label_count {
        eprintln!(
            "[tbs] FAIL: num_labels ({}) > owner_label_count ({})",
            num_labels, owner_label_count
        );
        return None;
    }

    let canonical_owner = match reconstruct_wildcard_name(&owner, num_labels) {
        Some(n) => n,
        None => {
            eprintln!("[tbs] FAIL: reconstruct_wildcard_name returned None");
            return None;
        }
    };
    eprintln!("[tbs] canonical_owner = {}", canonical_owner);

    let mut rrset: Vec<&Record> = records
        .iter()
        .filter(|r| {
            r.name() == &owner
                && r.record_type() == type_covered
                && r.dns_class() == rrsig_class
        })
        .collect();

    eprintln!("[tbs] rrset after name/type/class filter: {}", rrset.len());

    if rrset.is_empty() {
        if let Some(first) = records.first() {
            eprintln!(
                "[tbs]   first input record: name={} type={:?} class={:?}",
                first.name(), first.record_type(), first.dns_class(),
            );
        }
        return None;
    }

    let mut sortable: Vec<(Vec<u8>, &Record)> = Vec::with_capacity(rrset.len());
    for r in rrset.drain(..) {
        let bytes = match canonical_rdata(r) {
            Some(b) => b,
            None => {
                eprintln!("[tbs] FAIL: canonical_rdata failed for {}", r.name());
                return None;
            }
        };
        sortable.push((bytes, r));
    }
    sortable.sort_by(|a, b| a.0.cmp(&b.0));
    let rrset: Vec<&Record> = sortable.into_iter().map(|(_, r)| r).collect();

    let mut buf: Vec<u8> = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut buf);
        encoder.set_canonical_names(true);

        macro_rules! e {
            ($expr:expr) => {
                match $expr {
                    Ok(()) => {}
                    Err(err) => {
                        eprintln!("[tbs] FAIL at {}: {}", stringify!($expr), err);
                        return None;
                    }
                }
            };
        }

        e!(encoder.emit_u16(u16::from(type_covered)));
        e!(encoder.emit_u8(u8::from(rrsig.algorithm())));
        e!(encoder.emit_u8(num_labels));
        e!(encoder.emit_u32(rrsig.original_ttl()));
        e!(encoder.emit_u32(rrsig.sig_expiration().get()));
        e!(encoder.emit_u32(rrsig.sig_inception().get()));
        e!(encoder.emit_u16(rrsig.key_tag()));
        e!(rrsig.signer_name().emit(&mut encoder));

        for record in &rrset {
            e!(canonical_owner.emit(&mut encoder));
            e!(encoder.emit_u16(u16::from(type_covered)));
            e!(encoder.emit_u16(u16::from(rrsig_class)));
            e!(encoder.emit_u32(rrsig.original_ttl()));

            let rdata = match canonical_rdata(record) {
                Some(b) => b,
                None => {
                    eprintln!("[tbs] FAIL: canonical_rdata for emit");
                    return None;
                }
            };
            let rdata_len = match u16::try_from(rdata.len()) {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("[tbs] FAIL: rdata too long ({})", rdata.len());
                    return None;
                }
            };
            e!(encoder.emit_u16(rdata_len));
            for b in &rdata {
                e!(encoder.emit_u8(*b));
            }
        }
    }

    Some(buf)
}

fn canonical_rdata(record: &Record) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
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
    eprintln!("[tbs] wildcard reconstruction: {} -> {}", owner, wildcard);
    Name::from_str(&wildcard).ok()
}
