// src/dnssec/crypto.rs

use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, RRSIG};
use hickory_proto::dnssec::Algorithm;
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

use ml_dsa::signature::Verifier;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature as MlDsaSignature,
    VerifyingKey as MlDsaVerifyingKey,
};

use ring::digest;
use ring::signature;

use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey as RsaVK};
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey};

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

pub const PER_VALIDATION_MAX_SIG_CHECKS: usize = 24;

/// Minimum RSA modulus size (in bytes) that `ring`'s
/// RSA_PKCS1_2048_8192_SHA* parameter set will accept.
const RING_RSA_MIN_MODULUS_BYTES: usize = 256; // 2048 bits

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

/// Validate an RRSIG's 32-bit DNSSEC serial-number validity window.
///
/// DNSSEC timestamps are 32-bit serial numbers, so comparisons must use
/// serial-number arithmetic rather than ordinary u64 comparisons.
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

/// Calculate the DNSSEC key tag for a DNSKEY.
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

/// Calculate a DNSKEY DS digest.
///
/// digest_type:
///   1 = SHA-1
///   2 = SHA-256
///   4 = SHA-384
pub fn compute_ds_digest(
    owner: &Name,
    dnskey: &DNSKEY,
    digest_type: u8,
) -> Option<Vec<u8>> {
    let mut buf = Vec::new();

    {
        let mut encoder = BinEncoder::new(&mut buf);
        encoder.set_canonical_names(true);

        owner.emit(&mut encoder).ok()?;
        dnskey.emit(&mut encoder).ok()?;
    }

    match digest_type {
        1 => Some(
            digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &buf)
                .as_ref()
                .to_vec(),
        ),
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
        .map(|i| {
            s.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect()
}

/// Build the DNSSEC "to be signed" data for an RRSIG.
///
/// hickory-proto 0.25.2's TBS::from_rrsig() emits only the RRSIG
/// RDATA prefix and silently drops the RRset records, producing a
/// truncated TBS (~26 bytes for uk.com instead of ~48). This function
/// delegates to crate::dnssec::manual_tbs which implements
/// RFC 4034 §3.1.8.1 directly.
pub fn build_tbs(
    rrsig_record: &Record,
    records: &[Record],
) -> Option<Vec<u8>> {
    crate::dnssec::manual_tbs::build_tbs_manual(rrsig_record, records)
}

/// Verify a DNSSEC signature using the supplied DNSKEY algorithm.
pub fn verify_signature(
    algorithm: Algorithm,
    pubkey_bytes: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
    match algorithm {
        /*
         * Algorithm 5  (RSASHA1) and
         * Algorithm 7  (RSASHA1-NSEC3-SHA1)
         *
         * RFC 5155 §2 defines algorithm 7 as an alias for algorithm 5.
         * The signature is the exact same RSA/SHA-1 PKCS#1 v1.5 blob
         * over the exact same TBS. The NSEC3 distinction only affects
         * the algorithm identifier and the denial-of-existence records.
         *
         * ring's RSA_PKCS1_2048_8192_SHA1 parameter set refuses moduli
         * smaller than 2048 bits. Many legacy algorithm-5/7 zones
         * (e.g. CentralNic .com style zones such as uk.com, eu.com,
         * us.com) still publish 1024-bit RSA ZSKs, so we fall back to
         * the pure-Rust `rsa` crate, which has no modulus size floor.
         */
        Algorithm::RSASHA1 | Algorithm::RSASHA1NSEC3SHA1 => {
            let Some((exponent, modulus)) = parse_rsa_public_key(pubkey_bytes) else {
                tracing::debug!(
                    alg = ?algorithm,
                    "[crypto] Failed to parse RSA public key"
                );
                return false;
            };

            tracing::debug!(
                alg = ?algorithm,
                modulus_bits = modulus.len() * 8,
                tbs_len = message.len(),
                sig_len = sig.len(),
                "[crypto] RSA/SHA-1 verification attempt"
            );

            if modulus.len() >= RING_RSA_MIN_MODULUS_BYTES {
                let components = signature::RsaPublicKeyComponents {
                    n: modulus,
                    e: exponent,
                };

                if components
                    .verify(
                        &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
                        message,
                        sig,
                    )
                    .is_ok()
                {
                    return true;
                }
            } else {
                tracing::debug!(
                    modulus_bits = modulus.len() * 8,
                    "[crypto] RSA modulus below ring's 2048-bit floor; \
                     using pure-Rust rsa fallback"
                );
            }

            verify_rsa_sha1_via_rsa_crate(exponent, modulus, message, sig)
        }

        Algorithm::RSASHA256 | Algorithm::RSASHA512 => {
            let Some((exponent, modulus)) = parse_rsa_public_key(pubkey_bytes) else {
                return false;
            };

            let verify_alg: &'static signature::RsaParameters =
                if algorithm == Algorithm::RSASHA256 {
                    &signature::RSA_PKCS1_2048_8192_SHA256
                } else {
                    &signature::RSA_PKCS1_2048_8192_SHA512
                };

            let components = signature::RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            };

            if components.verify(verify_alg, message, sig).is_ok() {
                return true;
            }

            if modulus.len() < RING_RSA_MIN_MODULUS_BYTES
                && algorithm == Algorithm::RSASHA256
            {
                return verify_rsa_sha256_via_rsa_crate(exponent, modulus, message, sig);
            }

            false
        }

        Algorithm::ECDSAP256SHA256 => {
            let mut full_key = Vec::with_capacity(65);
            full_key.push(0x04);
            full_key.extend_from_slice(pubkey_bytes);

            let key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_FIXED,
                &full_key,
            );

            key.verify(message, sig).is_ok()
        }

        Algorithm::ECDSAP384SHA384 => {
            let mut full_key = Vec::with_capacity(97);
            full_key.push(0x04);
            full_key.extend_from_slice(pubkey_bytes);

            let key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P384_SHA384_FIXED,
                &full_key,
            );

            key.verify(message, sig).is_ok()
        }

        Algorithm::ED25519 => {
            let key = signature::UnparsedPublicKey::new(
                &signature::ED25519,
                pubkey_bytes,
            );

            key.verify(message, sig).is_ok()
        }

        Algorithm::Unknown(18) => verify_mldsa44(pubkey_bytes, message, sig),

        _ => false,
    }
}

/// Pure-Rust RSA/SHA-1 PKCS#1 v1.5 verification via the `rsa` crate.
/// Used as the fallback for algorithm 5 / 7 DNSKEYs whose modulus is
/// below ring's 2048-bit floor.
fn verify_rsa_sha1_via_rsa_crate(
    exponent: &[u8],
    modulus: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from_bytes_be(exponent);

    let Ok(key) = RsaPublicKey::new(n, e) else {
        tracing::debug!("[crypto] rsa crate rejected RSA public key");
        return false;
    };

    let vk = RsaVK::<Sha1>::new(key);

    let Ok(sig_obj) = RsaSig::try_from(sig) else {
        tracing::debug!(
            sig_len = sig.len(),
            "[crypto] rsa crate could not parse PKCS#1 v1.5 signature"
        );
        return false;
    };

    match vk.verify(message, &sig_obj) {
        Ok(()) => {
            tracing::debug!("[crypto] rsa crate RSA/SHA-1 verification OK");
            true
        }
        Err(e) => {
            tracing::debug!(
                error = %e,
                "[crypto] rsa crate RSA/SHA-1 verification failed"
            );
            false
        }
    }
}

/// Pure-Rust RSA/SHA-256 PKCS#1 v1.5 verification via the `rsa` crate.
/// Used as the fallback for algorithm 8 DNSKEYs whose modulus is below
/// ring's 2048-bit floor.
fn verify_rsa_sha256_via_rsa_crate(
    exponent: &[u8],
    modulus: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from_bytes_be(exponent);

    let Ok(key) = RsaPublicKey::new(n, e) else {
        tracing::debug!("[crypto] rsa crate rejected RSA public key");
        return false;
    };

    let vk = RsaVK::<Sha256>::new(key);

    let Ok(sig_obj) = RsaSig::try_from(sig) else {
        tracing::debug!(
            sig_len = sig.len(),
            "[crypto] rsa crate could not parse PKCS#1 v1.5 signature"
        );
        return false;
    };

    match vk.verify(message, &sig_obj) {
        Ok(()) => {
            tracing::debug!("[crypto] rsa crate RSA/SHA-256 verification OK");
            true
        }
        Err(e) => {
            tracing::debug!(
                error = %e,
                "[crypto] rsa crate RSA/SHA-256 verification failed"
            );
            false
        }
    }
}

/// Verify an ML-DSA-44 DNSSEC signature.
pub fn verify_mldsa44(
    pubkey_bytes: &[u8],
    message: &[u8],
    sig: &[u8],
) -> bool {
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

/// Parse the DNSSEC wire-format RSA public key.
///
/// DNSKEY RSA public keys are encoded as:
///
///   exponent length (1 or 3 bytes)
///   exponent
///   modulus
///
/// If the first length byte is zero, the exponent length is encoded
/// as a 16-bit value in the next two bytes.
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

    if exp_len == 0 || rest.len() < exp_len {
        return None;
    }

    let (exponent, modulus) = rest.split_at(exp_len);

    // Sanity bounds. Floor is 64 bytes (512 bits) so legacy short keys
    // can still route through the `rsa` crate fallback.
    if modulus.is_empty() || modulus.len() < 64 || modulus.len() > 1024 {
        return None;
    }

    Some((exponent, modulus))
}
