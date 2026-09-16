// src/dnssec/chain.rs
use super::crypto::{compute_ds_digest, compute_key_tag, hex_decode, KeyTagExt, ValidationBudget};
use super::negative::{validate_nsec, validate_nsec3};
use super::validator::{DnssecStatus, DnssecValidator};
use crate::cache::now_secs;
use crate::recursor::{calculate_min_ttl, RecursiveResolver};
use dashmap::DashMap;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS};
use hickory_proto::dnssec::PublicKey;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::sync::OnceLock;

/// Case-insensitive DNS name comparison (RFC 4343).
pub fn name_eq(a: &Name, b: &Name) -> bool {
    a.to_ascii().eq_ignore_ascii_case(&b.to_ascii())
}

pub const ROOT_TRUST_ANCHORS: &[(u16, u8, u8, &str)] = &[
    (
        20326,
        8,
        2,
        "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    ),
    (
        38696,
        8,
        2,
        "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
    ),
];

pub struct CachedZoneKeys {
    pub keys: Vec<DNSKEY>,
    pub expires_at: u64,
}

pub fn key_trust_cache() -> &'static DashMap<String, CachedZoneKeys> {
    static CACHE: OnceLock<DashMap<String, CachedZoneKeys>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneSignedness {
    Signed,
    ProvenUnsigned,
    Unknown,
}

pub struct SignedZoneEntry {
    pub signedness: ZoneSignedness,
    pub expires_at: u64,
}

pub fn signed_zone_cache() -> &'static DashMap<String, SignedZoneEntry> {
    static CACHE: OnceLock<DashMap<String, SignedZoneEntry>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

#[derive(Debug, Clone)]
pub enum ChainResult {
    Trusted { keys: Vec<DNSKEY>, ttl: u32 },
    Unsigned { ttl: u32 },
    Bogus,
}

pub async fn build_trust_chain(
    recursor: &RecursiveResolver,
    target_zone: &Name,
    budget: &mut ValidationBudget,
) -> ChainResult {
    let mut path = Vec::new();
    let mut cur = target_zone.clone();

    loop {
        path.push(cur.clone());

        if cur.is_root() {
            break;
        }

        cur = cur.base_name();
    }

    path.reverse();

    let cache = key_trust_cache();
    let mut trusted_parent_keys: Option<Vec<DNSKEY>> = None;
    let mut last_ttl = 300u32;

    for zone in &path {
        let zone_key = zone.to_string().to_lowercase();

        if let Some(cached) = cache.get(&zone_key) {
            if cached.expires_at > now_secs() {
                trusted_parent_keys = Some(cached.keys.clone());
                continue;
            }
        }

        let mut parent_ds_ttl = 300u32;

        let trusted_ds: Vec<(u16, u8, u8, Vec<u8>)> = if zone.is_root() {
            ROOT_TRUST_ANCHORS
                .iter()
                .filter_map(|(tag, alg, digest_type, hex)| {
                    hex_decode(hex).map(|bytes| (*tag, *alg, *digest_type, bytes))
                })
                .collect()
        } else {
            let parent_keys = match &trusted_parent_keys {
                Some(k) => k,
                None => {
                    tracing::warn!(
                        zone = %zone,
                        "[DNSSEC] No trusted parent keys available; Bogus"
                    );
                    return ChainResult::Bogus;
                }
            };

            let ds_msg = match recursor.resolve(zone, RecordType::DS).await {
                Ok(m) => m,
                Err(err) => {
                    tracing::warn!(
                        zone = %zone,
                        error = %err,
                        "[DNSSEC] Failed to fetch DS; Bogus (fail-closed)"
                    );
                    return ChainResult::Bogus;
                }
            };

            let ds_ttl = calculate_min_ttl(&ds_msg);
            parent_ds_ttl = ds_ttl;

            let ds_records: Vec<DS> = ds_msg
                .answers()
                .iter()
                .filter(|r| name_eq(r.name(), zone))
                .filter_map(|r| match r.data() {
                    RData::DNSSEC(DNSSECRData::DS(d)) => Some(d.clone()),
                    _ => None,
                })
                .collect();

            if ds_records.is_empty() {
                let authority = ds_msg.name_servers();

                let denial_status = if authority
                    .iter()
                    .any(|r| r.record_type() == RecordType::NSEC3)
                {
                    validate_nsec3(
                        parent_keys,
                        zone,
                        RecordType::DS,
                        authority,
                        budget,
                    )
                } else if authority
                    .iter()
                    .any(|r| r.record_type() == RecordType::NSEC)
                {
                    validate_nsec(
                        parent_keys,
                        zone,
                        RecordType::DS,
                        authority,
                        budget,
                    )
                } else {
                    DnssecStatus::Bogus
                };

                match denial_status {
                    DnssecStatus::Secure | DnssecStatus::InsecureUnsigned => {
                        let ds_proof_ttl = calculate_min_ttl(&ds_msg);

                        tracing::debug!(
                            zone = %zone,
                            "[DNSSEC] Authenticated denial of DS verified: zone is Insecure"
                        );

                        signed_zone_cache().insert(
                            zone.to_string().to_lowercase(),
                            SignedZoneEntry {
                                signedness: ZoneSignedness::ProvenUnsigned,
                                expires_at: now_secs() + ds_proof_ttl.min(86400) as u64,
                            },
                        );

                        return ChainResult::Unsigned {
                            ttl: ds_proof_ttl,
                        };
                    }

                    _ => {
                        tracing::warn!(
                            zone = %zone,
                            denial_status = ?denial_status,
                            "[DNSSEC] DS missing but denial proof failed; Bogus (fail-closed)"
                        );

                        return ChainResult::Bogus;
                    }
                }
            }

            let ds_rrsig_records: Vec<Record> = ds_msg
                .answers()
                .iter()
                .filter(|r| {
                    name_eq(r.name(), zone)
                        && matches!(
                            r.data(),
                            RData::DNSSEC(DNSSECRData::RRSIG(s))
                                if s.type_covered() == RecordType::DS
                        )
                })
                .cloned()
                .collect();

            if ds_rrsig_records.is_empty() {
                tracing::warn!(
                    zone = %zone,
                    "[DNSSEC] DS RRset has no RRSIG; Bogus"
                );
                return ChainResult::Bogus;
            }

            let ds_full_records: Vec<Record> = ds_msg
                .answers()
                .iter()
                .filter(|r| {
                    r.record_type() == RecordType::DS && name_eq(r.name(), zone)
                })
                .cloned()
                .collect();

            let mut ds_verified = false;

            'ds: for rrsig_record in &ds_rrsig_records {
                let rrsig = match rrsig_record.data() {
                    RData::DNSSEC(DNSSECRData::RRSIG(sig))
                        if sig.type_covered() == RecordType::DS =>
                    {
                        sig
                    }
                    _ => continue,
                };

                for key in parent_keys {
                    if key.key_tag_matches(rrsig.key_tag()) {
                        if !budget.can_check_sig() {
                            tracing::warn!(
                                "[DNSSEC] Work budget exhausted verifying DS; Bogus"
                            );
                            return ChainResult::Bogus;
                        }

                        if DnssecValidator::verify_rrsig(
                            rrsig,
                            key,
                            rrsig_record,
                            &ds_full_records,
                        ) {
                            ds_verified = true;
                            break 'ds;
                        }
                    }
                }
            }

            if !ds_verified {
                tracing::warn!(
                    zone = %zone,
                    "[DNSSEC] Parent DS signature did not verify; Bogus"
                );
                return ChainResult::Bogus;
            }

            let anchors: Vec<(u16, u8, u8, Vec<u8>)> = ds_records
                .iter()
                .filter_map(|d| {
                    let dt = u8::from(d.digest_type());
                    let alg = u8::from(d.algorithm());

                    let alg_supported =
                        matches!(alg, 5 | 7 | 8 | 10 | 13 | 14 | 15 | 18);

                    if (dt == 1 || dt == 2 || dt == 4) && alg_supported {
                        Some((d.key_tag(), alg, dt, d.digest().to_vec()))
                    } else {
                        None
                    }
                })
                .collect();

            if anchors.is_empty() {
                let ds_ttl = calculate_min_ttl(&ds_msg);

                tracing::warn!(
                    zone = %zone,
                    "[DNSSEC] DS RRset has no supported digest/algorithm anchors; Unsigned"
                );

                signed_zone_cache().insert(
                    zone.to_string().to_lowercase(),
                    SignedZoneEntry {
                        signedness: ZoneSignedness::ProvenUnsigned,
                        expires_at: now_secs() + ds_ttl.min(86400) as u64,
                    },
                );

                return ChainResult::Unsigned {
                    ttl: ds_ttl,
                };
            }

            anchors
        };

        let dnskey_msg = match recursor.resolve(zone, RecordType::DNSKEY).await {
            Ok(m) => m,
            Err(err) => {
                tracing::warn!(
                    zone = %zone,
                    error = %err,
                    "[DNSSEC] Failed to fetch DNSKEY; Bogus (fail-closed)"
                );
                return ChainResult::Bogus;
            }
        };

        let candidates: Vec<DNSKEY> = dnskey_msg
            .answers()
            .iter()
            .filter(|r| name_eq(r.name(), zone))
            .filter_map(|r| match r.data() {
                RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
                _ => None,
            })
            .collect();

        if candidates.is_empty() {
            tracing::warn!(
                zone = %zone,
                "[DNSSEC] DNSKEY query returned no keys; Bogus"
            );
            return ChainResult::Bogus;
        }

        let dnskey_rrsig_records: Vec<Record> = dnskey_msg
            .answers()
            .iter()
            .filter(|r| {
                name_eq(r.name(), zone)
                    && matches!(
                        r.data(),
                        RData::DNSSEC(DNSSECRData::RRSIG(s))
                            if s.type_covered() == RecordType::DNSKEY
                    )
            })
            .cloned()
            .collect();

        if dnskey_rrsig_records.is_empty() {
            tracing::warn!(
                zone = %zone,
                "[DNSSEC] DNSKEY RRset has no RRSIG; Bogus"
            );
            return ChainResult::Bogus;
        }

        let mut matched_keys: Vec<DNSKEY> = Vec::new();

        for cand in &candidates {
            let cand_tag = compute_key_tag(cand).unwrap_or(u16::MAX);
            let cand_alg = u8::from(cand.public_key().algorithm());

            for (tag, alg, digest_type, digest) in &trusted_ds {
                if *tag == cand_tag && *alg == cand_alg {
                    if let Some(computed) =
                        compute_ds_digest(zone, cand, *digest_type)
                    {
                        if &computed == digest {
                            matched_keys.push(cand.clone());
                        }
                    }
                }
            }
        }

        if matched_keys.is_empty() {
            tracing::warn!(
                zone = %zone,
                "[DNSSEC] Parent DS matches no published DNSKEY; returning Bogus"
            );
            return ChainResult::Bogus;
        }

        let dnskey_full_records: Vec<Record> = dnskey_msg
            .answers()
            .iter()
            .filter(|r| {
                r.record_type() == RecordType::DNSKEY && name_eq(r.name(), zone)
            })
            .cloned()
            .collect();

        tracing::debug!(
            zone = %zone,
            full_records = dnskey_full_records.len(),
            candidates = candidates.len(),
            matched_keys = matched_keys.len(),
            "[DNSSEC] DNSKEY RRset assembled for verification"
        );

        let mut dnskey_verified = false;

        'dk: for rrsig_record in &dnskey_rrsig_records {
            let rrsig = match rrsig_record.data() {
                RData::DNSSEC(DNSSECRData::RRSIG(sig))
                    if sig.type_covered() == RecordType::DNSKEY =>
                {
                    sig
                }
                _ => continue,
            };

            for key in &matched_keys {
                if key.key_tag_matches(rrsig.key_tag()) {
                    if !budget.can_check_sig() {
                        tracing::warn!(
                            "[DNSSEC] Work budget exhausted verifying DNSKEY; Bogus"
                        );
                        return ChainResult::Bogus;
                    }

                    if DnssecValidator::verify_rrsig(
                        rrsig,
                        key,
                        rrsig_record,
                        &dnskey_full_records,
                    ) {
                        dnskey_verified = true;
                        break 'dk;
                    }
                }
            }
        }

        if !dnskey_verified {
            tracing::warn!(
                zone = %zone,
                "[DNSSEC] DNSKEY RRset signature did not verify; returning Bogus"
            );
            return ChainResult::Bogus;
        }

        let dnskey_ttl = calculate_min_ttl(&dnskey_msg);

        let effective_ttl = if zone.is_root() {
            dnskey_ttl
        } else {
            dnskey_ttl.min(parent_ds_ttl)
        };

        last_ttl = effective_ttl;

        let authenticated_zone_keys: Vec<DNSKEY> = candidates
            .into_iter()
            .filter(|k| (k.flags() & 0x0100) != 0)
            .collect();

        cache.insert(
            zone_key,
            CachedZoneKeys {
                keys: authenticated_zone_keys.clone(),
                expires_at: now_secs() + effective_ttl as u64,
            },
        );

        trusted_parent_keys = Some(authenticated_zone_keys);
    }

    match trusted_parent_keys {
        Some(keys) => ChainResult::Trusted {
            keys,
            ttl: last_ttl,
        },
        None => ChainResult::Unsigned { ttl: last_ttl },
    }
}

pub async fn find_zone_apex(
    recursor: &RecursiveResolver,
    name: &Name,
) -> Option<Name> {
    let mut candidate = name.clone();

    loop {
        if let Ok(msg) = recursor.resolve(&candidate, RecordType::SOA).await {
            for ans in msg.answers() {
                if name_eq(ans.name(), &candidate)
                    && ans.record_type() == RecordType::SOA
                {
                    return Some(candidate);
                }
            }

            let is_cname = msg
                .answers()
                .iter()
                .any(|r| {
                    name_eq(r.name(), &candidate)
                        && r.record_type() == RecordType::CNAME
                });

            if !is_cname {
                let mut best_soa: Option<Name> = None;

                for rec in msg
                    .answers()
                    .iter()
                    .chain(msg.name_servers().iter())
                {
                    if matches!(rec.data(), RData::SOA(_)) {
                        let soa_name = rec.name();

                        if name_eq(soa_name, name) || soa_name.zone_of(name) {
                            let is_better = match &best_soa {
                                Some(current) => {
                                    soa_name.num_labels() > current.num_labels()
                                }
                                None => true,
                            };

                            if is_better {
                                best_soa = Some(soa_name.clone());
                            }
                        }
                    }
                }

                if let Some(soa) = best_soa {
                    return Some(soa);
                }
            }
        }

        if candidate.is_root() {
            break;
        }

        candidate = candidate.base_name();
    }

    None
}

pub async fn is_zone_signed(
    recursor: &RecursiveResolver,
    name: &Name,
    budget: &mut ValidationBudget,
) -> ZoneSignedness {
    let cache = signed_zone_cache();

    let mut cur = name.clone();

    loop {
        let key = cur.to_string().to_lowercase();

        if let Some(entry) = cache.get(&key) {
            if entry.expires_at > now_secs() {
                match entry.signedness {
                    ZoneSignedness::ProvenUnsigned => {
                        return ZoneSignedness::ProvenUnsigned;
                    }

                    ZoneSignedness::Signed => {
                        if name_eq(&cur, name) {
                            return ZoneSignedness::Signed;
                        }
                    }

                    ZoneSignedness::Unknown => {}
                }
            }
        }

        if cur.is_root() {
            break;
        }

        cur = cur.base_name();
    }

    let zone = match find_zone_apex(recursor, name).await {
        Some(z) => z,
        None => {
            if name.is_root() {
                Name::root()
            } else {
                name.base_name()
            }
        }
    };

    let (signedness, proof_ttl) =
        match build_trust_chain(recursor, &zone, budget).await {
            ChainResult::Trusted { ttl, .. } => {
                (ZoneSignedness::Signed, ttl)
            }

            ChainResult::Unsigned { ttl } => {
                (ZoneSignedness::ProvenUnsigned, ttl)
            }

            ChainResult::Bogus => {
                (ZoneSignedness::Unknown, 0)
            }
        };

    if signedness != ZoneSignedness::Unknown {
        cache.insert(
            zone.to_string().to_lowercase(),
            SignedZoneEntry {
                signedness,
                expires_at: now_secs() + proof_ttl.min(86400) as u64,
            },
        );
    }

    tracing::debug!(
        zone = %zone,
        queried_name = %name,
        ?signedness,
        "[DNSSEC] is_zone_signed resolved"
    );

    signedness
}
