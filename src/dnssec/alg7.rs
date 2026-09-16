// src/dnssec/alg7.rs
//
// Standalone RSA/SHA-1 verifier for DNSSEC algorithm 7
// (RSASHA1-NSEC3-SHA1). This bypasses hickory-proto 0.25.2's broken
// crypto dispatch, which unconditionally rejects algorithm 7.
//
// RFC 5155 §2: "Algorithm 7, RSASHA1-NSEC3-SHA1 is an alias for
// algorithm 5, RSASHA1." The only difference is the algorithm
// identifier; the signature is computed over the same TBS with the
// same RSA/SHA-1 PKCS#1 v1.5 scheme.

use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::rr::{RData, Record};
use ring::signature;

/// Parse the DNSSEC wire-format RSA public key.
///
/// DNSKEY RSA public keys are encoded as:
///   exponent length (1 or 3 bytes)
///   exponent
///   modulus
///
/// If the first length byte is zero, the exponent length is a
/// 16-bit big-endian value in the following two bytes.
fn parse_rsa_public_key(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
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

    // Sanity bounds for DNSSEC RSA keys.
    if modulus.is_empty() || modulus.len() < 128 || modulus.len() > 1024 {
        return None;
    }

    Some((exponent, modulus))
}

/// Verify an algorithm-7 RRSIG using RSA/SHA-1.
///
/// `rrsig_record` must be the full RRSIG Record (not just the RDATA).
/// `records` must be the full RRset covered by the RRSIG.
/// `tbs` must be the canonical "to be signed" data produced by
/// Hickory's `TBS::from_rrsig` — that part of Hickory is correct.
pub fn verify_alg7_rrsig(
    rrsig: &RRSIG,
    dnskey: &DNSKEY,
    tbs: &[u8],
    sig: &[u8],
) -> bool {
    // The DNSKEY must be algorithm 7 (or the alias 5 — same crypto).
    let dnskey_alg = u8::from(dnskey.public_key().algorithm());
    if dnskey_alg != 7 && dnskey_alg != 5 {
        tracing::debug!(
            dnskey_alg,
            "[alg7] DNSKEY is not algorithm 7/5"
        );
        return false;
    }

    let pubkey_bytes = dnskey.public_key().public_bytes();

    let Some((exponent, modulus)) = parse_rsa_public_key(pubkey_bytes) else {
        tracing::debug!("[alg7] Failed to parse RSA public key");
        return false;
    };

    let components = signature::RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    };

    // Algorithm 7 uses the same RSA/SHA-1 PKCS#1 v1.5 scheme as
    // algorithm 5. ring exposes this as
    // RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY.
    components
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            tbs,
            sig,
        )
        .is_ok()
}
