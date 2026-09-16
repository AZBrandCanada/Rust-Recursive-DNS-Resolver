// verify_test/src/main.rs
//
// Live test: fetch uk.com / jra.go.jp / mhlw.go.jp / cmu.edu A + RRSIG
// + DNSKEY over DoH, build TBS with Hickory, verify the signature with
// both ring and the pure-Rust rsa crate, and print which path succeeds.

use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::dnssec::TBS;
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
    msg.extensions_mut().insert(edns);

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
    vk.verify(msg, &sig_obj)
        .map_err(|err| format!("verify: {err}"))
}

fn rsa_crate_sha256(e: &[u8], n: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let key = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
        .map_err(|err| format!("RsaPublicKey::new: {err}"))?;
    let vk = RsaVK::<Sha256>::new(key);
    let sig_obj = RsaSig::try_from(sig).map_err(|err| format!("sig parse: {err}"))?;
    vk.verify(msg, &sig_obj)
        .map_err(|err| format!("verify: {err}"))
}

async fn probe(domain: &str) {
    let name = Name::from_str(domain).unwrap();
    println!("\n===== {domain} A =====");

    let ans_msg = fetch(&name, RecordType::A).await;
    let key_msg = fetch(&name, RecordType::DNSKEY).await;

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

    let rrset: Vec<Record> = ans_msg
        .answers()
        .iter()
        .filter(|r| r.name() == &name && r.record_type() == rtype)
        .cloned()
        .collect();

    let typed_rrsig = Record::from_rdata(
        rrsig_rec.name().clone(),
        rrsig_rec.ttl(),
        rrsig.clone(),
    );
    let tbs = TBS::from_rrsig(&typed_rrsig, rrset.iter()).unwrap();

    println!(
        "RRSIG: alg={} tag={} labels={} sig_len={}",
        u8::from(rrsig.algorithm()),
        rrsig.key_tag(),
        rrsig.num_labels(),
        rrsig.sig().len(),
    );
    println!("TBS length: {}", tbs.as_ref().len());

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
            kalg,
            ktag,
            k.flags(),
            pub_bytes.len(),
        );

        let Some((e, n)) = parse_rsa_pubkey(pub_bytes) else {
            println!("  parse_rsa_pubkey failed");
            continue;
        };
        println!("  RSA modulus = {} bits", n.len() * 8);

        match kalg {
            5 | 7 => {
                let r_ring = ring_sha1(e, n, tbs.as_ref(), rrsig.sig());
                let r_rsa = rsa_crate_sha1(e, n, tbs.as_ref(), rrsig.sig());
                println!("  ring RSA/SHA1   : {r_ring}");
                println!("  rsa  RSA/SHA1   : {r_rsa:?}");
            }
            8 => {
                let r_ring = ring_sha256(e, n, tbs.as_ref(), rrsig.sig());
                let r_rsa = rsa_crate_sha256(e, n, tbs.as_ref(), rrsig.sig());
                println!("  ring RSA/SHA256 : {r_ring}");
                println!("  rsa  RSA/SHA256 : {r_rsa:?}");
            }
            _ => println!("  unsupported alg for this test"),
        }
    }
}

#[tokio::main]
async fn main() {
    for d in &["uk.com", "eu.com", "jra.go.jp", "mhlw.go.jp", "cmu.edu"] {
        probe(d).await;
    }
}
