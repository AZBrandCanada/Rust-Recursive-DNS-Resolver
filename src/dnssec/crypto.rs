// src/dnssec/crypto.rs
use hickory_proto::dnssec::rdata::{DNSKEY, RRSIG};
use hickory_proto::dnssec::Algorithm;
use hickory_proto::rr::{Name, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use ml_dsa::signature::Verifier;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey,
};
use ring::digest;
use ring::signature;
use sha2::{Digest, Sha256, Sha384};
use std::str::FromStr;

pub const PER_VALIDATION_MAX_SIG_CHECKS: usize = 24;

#[derive(Debug, Clone)]
pub struct ValidationBudget {
    sig_checks: usize,
    max_sig_checks: usize,
}

impl Default for ValidationBudget {
    fn default() -> Self {
        Self {
            sig_checks: 0,
            max_sig_checks: PER_VALIDATION_MAX_SIG_CHECKS,
        }
    }
}

impl ValidationBudget {
    pub fn can_check_sig(&mut self) -> bool {
        if self.sig_checks >= self.max_sig_checks {
            false
        } else {
            self.sig_checks += 1;
            true
        }
    }
}

pub fn rrsig_time_valid(sig: &RRSIG, now: u64) -> bool {
    let exp = sig.sig_expiration().get();
    let inc = sig.sig_inception().get();
    let now32 = (now & 0xFFFF_FFFF) as u32;

    (now32.wrapping_sub(inc) as i32) >= 0
        && (exp.wrapping_sub(now32) as i32) >= 0
        && (exp.wrapping_sub(inc) as i32) > 0
}

pub trait KeyTagExt {
    fn key_tag_matches(&self, tag: u16) -> bool;
}

impl KeyTagExt for DNSKEY {
    fn key_tag_matches(&self, tag: u16) -> bool {
        compute_key_tag(self).unwrap_or(u16::MAX) == tag
    }
}

pub fn compute_key_tag(dnskey: &DNSKEY) -> Option<u16> {
    if let Ok(tag) = dnskey.calculate_key_tag() {
        return Some(tag);
    }
    let mut buf = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut buf);
        dnskey.emit(&mut encoder).ok()?;
    }
    let mut ac: u32 = 0;
    for (i, b) in buf.iter().enumerate() {
        if i % 2 == 0 {
            ac += (*b as u32) << 8;
        } else {
            ac += *b as u32;
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    Some((ac & 0xFFFF) as u16)
}

pub fn compute_ds_digest(owner: &Name, dnskey: &DNSKEY, digest_type: u8) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut buf);
        encoder.set_canonical_names(true);
        owner.emit(&mut encoder).ok()?;
        dnskey.emit(&mut encoder).ok()?;
    }
    match digest_type {
        1 => Some(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &buf).as_ref().to_vec()),
        2 => Some(Sha256::digest(&buf).to_vec()),
        4 => Some(Sha384::digest(&buf).to_vec()),
        _ => None,
    }
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

pub fn build_tbs(rrsig: &RRSIG, owner: &Name, records: &[Record]) -> Option<Vec<u8>> {
    if records.is_empty() {
        return None;
    }

    let expected_type = rrsig.type_covered();
    let expected_class = records[0].dns_class();
    for rec in records {
        if rec.record_type() != expected_type
            || rec.dns_class() != expected_class
            || rec.name() != owner
        {
            return None;
        }
    }

    let mut out = Vec::new();
    out.extend_from_slice(&(u16::from(rrsig.type_covered()).to_be_bytes()));
    out.push(u8::from(rrsig.algorithm()));
    out.push(rrsig.num_labels());
    out.extend_from_slice(&rrsig.original_ttl().to_be_bytes());
    out.extend_from_slice(&rrsig.sig_expiration().get().to_be_bytes());
    out.extend_from_slice(&rrsig.sig_inception().get().to_be_bytes());
    out.extend_from_slice(&rrsig.key_tag().to_be_bytes());

    {
        let mut name_buf = Vec::new();
        let mut encoder = BinEncoder::new(&mut name_buf);
        encoder.set_canonical_names(true);
        let canonical_signer = rrsig.signer_name().to_lowercase();
        canonical_signer.emit(&mut encoder).ok()?;
        out.extend_from_slice(&name_buf);
    }

    let sig_labels = rrsig.num_labels() as usize;
    let owner_labels = owner.num_labels() as usize;

    let canonical_owner_raw = if owner_labels > sig_labels {
        let base = owner.trim_to(sig_labels);
        Name::from_str(&format!("*.{}", base)).unwrap_or_else(|_| owner.clone())
    } else {
        owner.clone()
    };

    let canonical_owner = canonical_owner_raw.to_lowercase();

    struct CanonicalEntry {
        rdata_bytes: Vec<u8>,
        full_wire: Vec<u8>,
    }

    let mut entries = Vec::new();

    for rec in records {
        let mut rdata_buf = Vec::new();
        {
            let mut rdata_encoder = BinEncoder::new(&mut rdata_buf);
            rdata_encoder.set_canonical_names(true);
            rec.data().emit(&mut rdata_encoder).ok()?;
        }

        let mut full_buf = Vec::new();
        {
            let mut encoder = BinEncoder::new(&mut full_buf);
            encoder.set_canonical_names(true);
            canonical_owner.emit(&mut encoder).ok()?;
            encoder.emit_u16(u16::from(rec.record_type())).ok()?;
            encoder.emit_u16(u16::from(rec.dns_class())).ok()?;
            encoder.emit_u32(rrsig.original_ttl()).ok()?;
            encoder.emit_u16(rdata_buf.len() as u16).ok()?;
            encoder.emit_vec(&rdata_buf).ok()?;
        }

        entries.push(CanonicalEntry {
            rdata_bytes: rdata_buf,
            full_wire: full_buf,
        });
    }

    entries.sort_by(|a, b| a.rdata_bytes.cmp(&b.rdata_bytes));

    for e in entries {
        out.extend_from_slice(&e.full_wire);
    }

    Some(out)
}

pub fn verify_signature(
    algorithm: Algorithm,
    pubkey_bytes: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
    match algorithm {
        Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1 => {
            let Some((exponent, modulus)) = parse_rsa_public_key(pubkey_bytes) else {
                return false;
            };
            let components = signature::RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            };
            components
                .verify(
                    &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
                    message,
                    sig,
                )
                .is_ok()
        }
        Algorithm::RSASHA256 | Algorithm::RSASHA512 => {
            let Some((exponent, modulus)) = parse_rsa_public_key(pubkey_bytes) else {
                return false;
            };
            let verify_alg: &'static signature::RsaParameters = if algorithm == Algorithm::RSASHA256
            {
                &signature::RSA_PKCS1_2048_8192_SHA256
            } else {
                &signature::RSA_PKCS1_2048_8192_SHA512
            };
            let components = signature::RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            };
            components.verify(verify_alg, message, sig).is_ok()
        }
        Algorithm::ECDSAP256SHA256 => {
            let mut full_key = Vec::with_capacity(65);
            full_key.push(0x04);
            full_key.extend_from_slice(pubkey_bytes);
            let key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &full_key);
            key.verify(message, sig).is_ok()
        }
        Algorithm::ECDSAP384SHA384 => {
            let mut full_key = Vec::with_capacity(97);
            full_key.push(0x04);
            full_key.extend_from_slice(pubkey_bytes);
            let key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &full_key);
            key.verify(message, sig).is_ok()
        }
        Algorithm::ED25519 => {
            let key = signature::UnparsedPublicKey::new(&signature::ED25519, pubkey_bytes);
            key.verify(message, sig).is_ok()
        }
        Algorithm::Unknown(18) => verify_mldsa44(pubkey_bytes, message, sig),
        _ => false,
    }
}

pub fn verify_mldsa44(pubkey_bytes: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let Ok(vk_enc) = EncodedVerifyingKey::<MlDsa44>::try_from(pubkey_bytes) else {
        tracing::debug!(
            len = pubkey_bytes.len(),
            "[DNSSEC] ML-DSA-44 public key has wrong length (expected 1312)"
        );
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa44>::decode(&vk_enc);

    let Ok(sig_enc) = EncodedSignature::<MlDsa44>::try_from(sig) else {
        tracing::debug!(
            len = sig.len(),
            "[DNSSEC] ML-DSA-44 signature has wrong length (expected 2420)"
        );
        return false;
    };
    let Some(sig_obj) = MlDsaSignature::<MlDsa44>::decode(&sig_enc) else {
        tracing::debug!("[DNSSEC] ML-DSA-44 signature decode failed");
        return false;
    };

    vk.verify(message, &sig_obj).is_ok()
}

pub fn parse_rsa_public_key(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
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
    if rest.len() < exp_len {
        return None;
    }
    let (exponent, modulus) = rest.split_at(exp_len);
    if modulus.is_empty() || modulus.len() < 128 || modulus.len() > 1024 {
        return None;
    }
    Some((exponent, modulus))
}
