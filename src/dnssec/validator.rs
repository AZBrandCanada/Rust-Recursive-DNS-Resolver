// src/dnssec/validator.rs
use super::chain::{build_trust_chain, is_zone_signed, ChainResult, ZoneSignedness};
use super::crypto::{
    build_tbs, compute_key_tag, rrsig_time_valid, verify_signature,
    ValidationBudget,
};
use super::negative::validate_negative;
use crate::cache::now_secs;
use crate::recursor::{
    dname_substitute, extract_dname_target, RecursiveResolver, DNAME_RECORD_TYPE,
};
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::dnssec::PublicKey;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_CNAME_CHAIN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnssecStatus {
    Secure,
    InsecureUnsigned,
    InsecureUnknown,
    Bogus,
}

#[derive(Debug, Clone)]
pub enum RedirectionStep {
    Cname {
        owner: Name,
        target: Name,
    },
    Dname {
        dname_owner: Name,
        #[allow(dead_code)]
        target: Name,
        input_name: Name,
        redirected_name: Name,
    },
}

#[derive(Debug)]
pub enum RedirectionChainResult {
    Complete(Vec<RedirectionStep>),
    Loop,
    TooLong,
}

pub struct DnssecValidator;

impl DnssecValidator {
    pub async fn validate_message(
        recursor: &RecursiveResolver,
        msg: &Message,
        qname: &Name,
        qtype: RecordType,
    ) -> DnssecStatus {
        let mut budget = ValidationBudget::default();

        Self::validate_message_with_budget(
            recursor,
            msg,
            qname,
            qtype,
            &mut budget,
        )
        .await
    }

    pub async fn validate_message_with_budget(
        recursor: &RecursiveResolver,
        msg: &Message,
        qname: &Name,
        qtype: RecordType,
        budget: &mut ValidationBudget,
    ) -> DnssecStatus {
        match msg.response_code() {
            ResponseCode::NXDomain => {
                validate_negative(recursor, msg, qname, qtype, budget).await
            }

            ResponseCode::NoError if msg.answers().is_empty() => {
                validate_negative(recursor, msg, qname, qtype, budget).await
            }

            ResponseCode::NoError => {
                let answers: Vec<Record> = msg.answers().to_vec();

                Self::validate_answer(
                    recursor,
                    qname,
                    qtype,
                    &answers,
                    budget,
                )
                .await
            }

            _ => DnssecStatus::InsecureUnknown,
        }
    }

    pub async fn validate_answer(
        recursor: &RecursiveResolver,
        name: &Name,
        rtype: RecordType,
        all_records: &[Record],
        budget: &mut ValidationBudget,
    ) -> DnssecStatus {
        let chain = if rtype == RecordType::CNAME {
            Vec::new()
        } else {
            match collect_redirection_chain(name, all_records) {
                RedirectionChainResult::Complete(c) => c,

                RedirectionChainResult::Loop => {
                    tracing::warn!(
                        name = %name,
                        "[DNSSEC] Redirection cycle detected; Bogus"
                    );

                    return DnssecStatus::Bogus;
                }

                RedirectionChainResult::TooLong => {
                    tracing::warn!(
                        name = %name,
                        "[DNSSEC] Redirection chain exceeded limit; Bogus"
                    );

                    return DnssecStatus::Bogus;
                }
            }
        };

        for step in &chain {
            match step {
                RedirectionStep::Cname { owner, .. } => {
                    let cname_records: Vec<Record> = all_records
                        .iter()
                        .filter(|r| {
                            r.name() == owner
                                && r.record_type() == RecordType::CNAME
                        })
                        .cloned()
                        .collect();

                    if cname_records.is_empty() {
                        return DnssecStatus::Bogus;
                    }

                    match Self::validate_rrset(
                        recursor,
                        owner,
                        RecordType::CNAME,
                        &cname_records,
                        all_records,
                        budget,
                    )
                    .await
                    {
                        DnssecStatus::Secure => {}

                        other => return other,
                    }
                }

                RedirectionStep::Dname {
                    dname_owner,
                    input_name,
                    ..
                } => {
                    let dname_records: Vec<Record> = all_records
                        .iter()
                        .filter(|r| {
                            r.name() == dname_owner
                                && r.record_type() == DNAME_RECORD_TYPE
                        })
                        .cloned()
                        .collect();

                    if dname_records.is_empty() {
                        return DnssecStatus::Bogus;
                    }

                    match Self::validate_rrset(
                        recursor,
                        dname_owner,
                        DNAME_RECORD_TYPE,
                        &dname_records,
                        all_records,
                        budget,
                    )
                    .await
                    {
                        DnssecStatus::Secure => {}

                        other => return other,
                    }

                    let synth_cname_records: Vec<Record> = all_records
                        .iter()
                        .filter(|r| {
                            r.name() == input_name
                                && r.record_type() == RecordType::CNAME
                        })
                        .cloned()
                        .collect();

                    let has_rrsig = all_records.iter().any(|r| match r.data() {
                        RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
                            sig.type_covered() == RecordType::CNAME
                                && r.name() == input_name
                        }

                        _ => false,
                    });

                    if !synth_cname_records.is_empty() && has_rrsig {
                        match Self::validate_rrset(
                            recursor,
                            input_name,
                            RecordType::CNAME,
                            &synth_cname_records,
                            all_records,
                            budget,
                        )
                        .await
                        {
                            DnssecStatus::Secure => {}

                            other => return other,
                        }
                    }
                }
            }
        }

        let final_owner = match chain.last() {
            Some(RedirectionStep::Cname { target, .. }) => target.clone(),

            Some(RedirectionStep::Dname {
                redirected_name, ..
            }) => redirected_name.clone(),

            None => name.clone(),
        };

        let target_records: Vec<Record> = all_records
            .iter()
            .filter(|r| {
                r.name() == &final_owner && r.record_type() == rtype
            })
            .cloned()
            .collect();

        if target_records.is_empty() {
            tracing::debug!(
                name = %name,
                final_owner = %final_owner,
                qtype = ?rtype,
                redirection_hops = chain.len(),
                "[DNSSEC] No records of requested type at final owner; treating as Unknown"
            );

            return DnssecStatus::InsecureUnknown;
        }

        Self::validate_rrset(
            recursor,
            &final_owner,
            rtype,
            &target_records,
            all_records,
            budget,
        )
        .await
    }

    pub async fn validate_rrset(
        recursor: &RecursiveResolver,
        owner: &Name,
        rtype: RecordType,
        target_records: &[Record],
        all_records: &[Record],
        budget: &mut ValidationBudget,
    ) -> DnssecStatus {
        /*
         * Keep the complete RRSIG Records here.
         *
         * We need the complete Record later because Hickory's DNSSEC TBS
         * builder requires the RRSIG record metadata as well as the RRSIG RDATA.
         */
        let rrsig_records: Vec<Record> = all_records
            .iter()
            .filter(|record| match record.data() {
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
                    sig.type_covered() == rtype && record.name() == owner
                }

                _ => false,
            })
            .cloned()
            .collect();

        if rrsig_records.is_empty() {
            return match is_zone_signed(recursor, owner, budget).await {
                ZoneSignedness::Signed => {
                    tracing::warn!(
                        owner = %owner,
                        qtype = ?rtype,
                        "[DNSSEC] Missing RRSIG for RRset in signed zone; Bogus"
                    );

                    DnssecStatus::Bogus
                }

                ZoneSignedness::ProvenUnsigned => {
                    tracing::debug!(
                        owner = %owner,
                        qtype = ?rtype,
                        "[DNSSEC] No RRSIG and zone proven unsigned; Insecure"
                    );

                    DnssecStatus::InsecureUnsigned
                }

                ZoneSignedness::Unknown => {
                    tracing::warn!(
                        owner = %owner,
                        qtype = ?rtype,
                        "[DNSSEC] No RRSIG and zone signedness unknown; Insecure (uncacheable)"
                    );

                    DnssecStatus::InsecureUnknown
                }
            };
        }

        let now = now_secs();

        /*
         * Store complete RRSIG Records rather than just RRSIG RDATA.
         */
        let mut candidates: Vec<Record> = Vec::new();

        for rrsig_record in &rrsig_records {
            let rrsig = match rrsig_record.data() {
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) => sig,

                _ => continue,
            };

            if !rrsig_time_valid(rrsig, now) {
                tracing::debug!(
                    owner = %owner,
                    sig_exp = rrsig.sig_expiration().get(),
                    sig_inc = rrsig.sig_inception().get(),
                    now,
                    "[DNSSEC] Skipping RRSIG outside validity window"
                );

                continue;
            }

            /*
             * RFC 4035 requires the RRSIG signer name to identify the
             * zone containing the covered RRset.
             */
            let zone = rrsig.signer_name();

            if !zone.zone_of(owner) && zone != owner {
                tracing::warn!(
                    owner = %owner,
                    signer = %zone,
                    "[DNSSEC] Skipping unauthorized signer for RRset"
                );

                continue;
            }

            /*
             * The RRSIG Labels field cannot exceed the number of labels
             * in the covered owner name.
             */
            if rrsig.num_labels() > owner.num_labels() {
                tracing::warn!(
                    owner = %owner,
                    signer = %zone,
                    rrsig_labels = rrsig.num_labels(),
                    owner_labels = owner.num_labels(),
                    "[DNSSEC] RRSIG has more labels than covered owner; Bogus"
                );

                continue;
            }

            candidates.push(rrsig_record.clone());
        }

        if candidates.is_empty() {
            tracing::warn!(
                owner = %owner,
                qtype = ?rtype,
                rrsig_count = rrsig_records.len(),
                "[DNSSEC] All RRSIGs were expired, not yet valid, or unauthorized; Bogus"
            );

            return DnssecStatus::Bogus;
        }

        let mut any_trusted_chain = false;

        for rrsig_record in candidates {
            let rrsig = match rrsig_record.data() {
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) => sig,

                _ => continue,
            };

            let zone = rrsig.signer_name();

            match build_trust_chain(recursor, zone, budget).await {
                ChainResult::Trusted {
                    keys: trusted_keys, ..
                } => {
                    any_trusted_chain = true;

                    /*
                     * Match the RRSIG key tag BEFORE consuming a crypto
                     * validation budget slot. This prevents unrelated
                     * DNSKEYs from exhausting the KeyTrap protection budget.
                     */
                    for dnskey in &trusted_keys {
                        let key_tag =
                            compute_key_tag(dnskey).unwrap_or(u16::MAX);

                        if key_tag != rrsig.key_tag() {
                            continue;
                        }

                        if !budget.can_check_sig() {
                            tracing::warn!(
                                name = %owner,
                                "[DNSSEC] Exceeded per-validation signature budget (KeyTrap protection); Bogus"
                            );

                            return DnssecStatus::Bogus;
                        }

                        // Log the algorithm and key size once per
                        // candidate so that any future regression in
                        // legacy RSA/SHA-1 handling is easy to diagnose.
                        let rrsig_alg = u8::from(rrsig.algorithm());
                        let dnskey_alg =
                            u8::from(dnskey.public_key().algorithm());

                        if rrsig_alg == 5 || rrsig_alg == 7 {
                            let pk_len =
                                dnskey.public_key().public_bytes().len();
                            tracing::debug!(
                                owner = %owner,
                                rrsig_alg,
                                dnskey_alg,
                                key_tag,
                                dnskey_pubkey_bytes = pk_len,
                                "[DNSSEC] Attempting legacy RSA/SHA-1 verification"
                            );
                        }

                        if Self::verify_rrsig(
                            rrsig,
                            dnskey,
                            &rrsig_record,
                            target_records,
                        ) {
                            return DnssecStatus::Secure;
                        }
                    }
                }

                ChainResult::Unsigned { .. } => {
                    tracing::debug!(
                        signer = %zone,
                        owner = %owner,
                        "[DNSSEC] Trust chain returned Unsigned for signer"
                    );
                }

                ChainResult::Bogus => {
                    return DnssecStatus::Bogus;
                }
            }
        }

        if any_trusted_chain {
            tracing::warn!(
                owner = %owner,
                qtype = ?rtype,
                rrsig_count = rrsig_records.len(),
                "[DNSSEC] No RRSIG verified against a trusted chain; Bogus"
            );

            return DnssecStatus::Bogus;
        }

        tracing::debug!(
            owner = %owner,
            qtype = ?rtype,
            "[DNSSEC] Validation fell through all RRSIGs with unsigned chains; Insecure"
        );

        DnssecStatus::InsecureUnsigned
    }

    pub fn verify_rrsig(
        rrsig: &RRSIG,
        dnskey: &DNSKEY,
        rrsig_record: &Record,
        records: &[Record],
    ) -> bool {
        let now = now_secs();

        if !rrsig_time_valid(rrsig, now) {
            tracing::debug!(
                owner = %rrsig_record.name(),
                sig_exp = rrsig.sig_expiration().get(),
                sig_inc = rrsig.sig_inception().get(),
                now,
                "[DNSSEC] RRSIG validity period violated"
            );

            return false;
        }

        if rrsig.algorithm() != dnskey.public_key().algorithm() {
            tracing::debug!(
                rrsig_alg = ?rrsig.algorithm(),
                dnskey_alg = ?dnskey.public_key().algorithm(),
                "[DNSSEC] Algorithm mismatch between RRSIG and DNSKEY"
            );

            return false;
        }

        let tbs = match build_tbs(rrsig_record, records) {
            Some(t) => t,

            None => {
                tracing::debug!(
                    owner = %rrsig_record.name(),
                    "[DNSSEC] Failed to build TBS for RRSIG"
                );

                return false;
            }
        };

        // Primary path: our own verify_signature(), which uses ring
        // first and falls back to the pure-Rust rsa crate for
        // algorithm 5 / 7 keys below ring's 2048-bit floor.
        if verify_signature(
            rrsig.algorithm(),
            dnskey.public_key().public_bytes(),
            &tbs,
            rrsig.sig(),
        ) {
            return true;
        }

        // Secondary path: Hickory's own verify(). Kept for the
        // algorithms Hickory does support, and as a safety net in case
        // our dispatch misses a variant.
        if dnskey.public_key().verify(&tbs, rrsig.sig()).is_ok() {
            return true;
        }

        tracing::debug!(
            owner = %rrsig_record.name(),
            alg = ?rrsig.algorithm(),
            key_tag = rrsig.key_tag(),
            "[DNSSEC] Both verify paths rejected RRSIG"
        );

        false
    }
}

pub fn collect_redirection_chain(
    name: &Name,
    records: &[Record],
) -> RedirectionChainResult {
    let mut chain = Vec::new();
    let mut current = name.clone();
    let mut seen: HashSet<Name> = HashSet::new();

    loop {
        if !seen.insert(current.clone()) {
            return RedirectionChainResult::Loop;
        }

        if chain.len() >= MAX_CNAME_CHAIN {
            return RedirectionChainResult::TooLong;
        }

        let cname_target = records.iter().find_map(|r| {
            if r.name() == &current && r.record_type() == RecordType::CNAME {
                if let RData::CNAME(c) = r.data() {
                    return Some(c.0.clone());
                }
            }

            None
        });

        if let Some(target) = cname_target {
            chain.push(RedirectionStep::Cname {
                owner: current.clone(),
                target: target.clone(),
            });

            current = target;
            continue;
        }

        let dname_step = records.iter().find_map(|r| {
            if r.record_type() == DNAME_RECORD_TYPE
                && r.name().zone_of(&current)
                && r.name() != &current
            {
                let target = extract_dname_target(r)?;
                let sub = dname_substitute(
                    &current,
                    r.name(),
                    &target,
                )
                .ok()?;

                return Some((r.name().clone(), target, sub));
            }

            None
        });

        if let Some((dname_owner, target, redirected_name)) = dname_step {
            chain.push(RedirectionStep::Dname {
                dname_owner,
                target,
                input_name: current.clone(),
                redirected_name: redirected_name.clone(),
            });

            current = redirected_name;
            continue;
        }

        break;
    }

    RedirectionChainResult::Complete(chain)
}
