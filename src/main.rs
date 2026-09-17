// src/main.rs
mod cache;
mod cache_config;
mod dnssec;
mod engine;
mod geo;
mod hit_tracker;
mod metrics;
mod prefetch;
mod ratelimit;
mod recursor;
mod root_zone;
mod singleflight;
mod tls;
mod tranco;
mod transports;

use cache::{
    create_cache, load_cache_from_disk, now_secs, save_cache_to_disk_async, CacheEntry, DnsCache,
    EntryKind,
};
use dashmap::DashMap;
use engine::{calculate_cache_ttl, AppState};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use recursor::RecursiveResolver;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use transports::quic::{bind_quic_endpoint, create_quic_server_config};
use transports::{
    build_doh_router, run_doh3_listener, run_doq_listener, run_dot_listener, run_tcp_listener,
    run_udp_listener,
};

/// Cache and Tranco paths. Read from the environment at first use,
/// defaulting to files relative to the process working directory.
fn cache_file() -> String {
    std::env::var("CACHE_FILE").unwrap_or_else(|_| "cache.json".to_string())
}

fn tranco_file() -> String {
    std::env::var("TRANCO_FILE").unwrap_or_else(|_| "tranco_list.txt".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,doh_server=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cache = create_cache();
    let recursor = RecursiveResolver::new();

    // ─── Geo-aware GSLB layer (Phase 1) ───────────────────────────────
    let geo_config = geo::GeoConfig::from_env();
    let geo_state: Option<std::sync::Arc<geo::GeoState>> = if geo_config.enabled {
        let state = geo::GeoState::new(geo_config.clone());
        let registry = state.health.clone();
        let cfg = geo_config.clone();
        tokio::spawn(async move {
            geo::health::run_loop(cfg, registry).await;
        });
        Some(state)
    } else {
        tracing::info!("[GEO] routing disabled (set GEO_ROUTING_ENABLED=1 to enable)");
        None
    };

    load_cache_from_disk(&cache, cache_file());

    {
        let cfg = cache_config::cache_config();
        tracing::info!(
            enabled = cfg.enabled,
            max_answer_entries = cfg.max_answer_entries,
            prefetch_enabled = cfg.prefetch_enabled,
            prefetch_threshold_pct = cfg.prefetch_threshold_pct,
            prefetch_min_hits = cfg.prefetch_min_hits,
            "[CACHE] Configuration loaded"
        );
    }

    // ─── Root zone (optional, managed lifecycle) ─────────────────────
    let _root_zone = root_zone::RootZoneManager::start(recursor.clone()).await;

    // ─── Cache pre-warming ───────────────────────────────────────────
    let warm_limit: usize = std::env::var("WARM_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let concurrency: usize = std::env::var("WARM_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);

    if warm_limit > 0 {
        tracing::info!(
            warm_limit,
            concurrency,
            "[WARM] Cache pre-warming enabled; starting warmup in 5 seconds"
        );
        let preloader_cache = cache.clone();
        let preloader_recursor = recursor.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            tracing::info!(warm_limit, "[WARM] Fetching Tranco domain list...");
            let domains = tranco::get_or_download_tranco(&tranco_file(), warm_limit).await;
            preload_domains(preloader_cache, preloader_recursor, domains, concurrency).await;
        });
    }

    // ─── Cache persistence ───────────────────────────────────────────
    let persist_cache = cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(120));
        loop {
            interval.tick().await;
            let count = persist_cache.entry_count();
            save_cache_to_disk_async(persist_cache.clone(), cache_file().to_string()).await;
            tracing::info!(entries = count, "[PERSIST] Cache synced to disk");
        }
    });

    // ─── Rate limiter ────────────────────────────────────────────────
    let rl_capacity: i64 = std::env::var("RATE_LIMIT_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let rl_per_sec: i64 = std::env::var("RATE_LIMIT_PER_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let rate_limiter = ratelimit::RateLimiter::new(rl_capacity, rl_per_sec);

    let dnssec_enforce = std::env::var("DNSSEC_ENFORCE")
        .map(|v| v != "0")
        .unwrap_or(true);

    if dnssec_enforce {
        tracing::info!("[DNSSEC] Enforcement ON: Broken/Bogus DNSSEC chains will return SERVFAIL");
    } else {
        tracing::warn!(
            "[DNSSEC] Enforcement OFF: Broken/Bogus DNSSEC chains will return records with AD=0"
        );
    }

    {
        let rl_cleanup = rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                rl_cleanup.cleanup(Duration::from_secs(900));
                tracing::debug!(
                    tracked_subnets = rl_cleanup.tracked_subnets(),
                    "[RATELIMIT] Cleanup pass completed"
                );
            }
        });
    }

    let app_state = AppState {
        cache: cache.clone(),
        recursor: recursor.clone(),
        rate_limiter,
        dnssec_enforce,
        geo: geo_state,
        singleflight: Arc::new(singleflight::SingleFlight::new()),
        in_flight: Arc::new(DashMap::new()),
    };

    // ─── Prefetch loop ───────────────────────────────────────────────
    {
        let prefetch_state = app_state.clone();
        tokio::spawn(async move {
            prefetch::prefetch_loop(prefetch_state).await;
        });
    }

    // ─── Listeners ───────────────────────────────────────────────────
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let requested_dns_port: u16 = std::env::var("DNS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(53);
    let requested_dot_port: u16 = std::env::var("DOT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(853);
    let requested_doq_port: u16 = std::env::var("DOQ_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(853);
    let requested_doh_port: u16 = std::env::var("DOH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);
    let requested_doh3_port: u16 = std::env::var("DOH3_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);
    let doh_no_tls = std::env::var("DOH_NO_TLS").ok().as_deref() == Some("1");

    let udp_semaphore = Arc::new(Semaphore::new(2048));
    let tcp_semaphore = Arc::new(Semaphore::new(512));
    let dot_semaphore = Arc::new(Semaphore::new(512));
    let doq_semaphore = Arc::new(Semaphore::new(512));
    let doh3_semaphore = Arc::new(Semaphore::new(512));

    let (udp_socket, active_dns_port) = bind_udp(&host, requested_dns_port, 5053).await?;
    let udp_socket = Arc::new(udp_socket);
    let udp_state = app_state.clone();
    let udp_sem = udp_semaphore.clone();
    tokio::spawn(async move {
        run_udp_listener(udp_socket, udp_state, udp_sem).await;
    });

    let (tcp_listener, _) = bind_tcp(&host, active_dns_port, 5053).await?;
    let tcp_state = app_state.clone();
    let tcp_sem = tcp_semaphore.clone();
    tokio::spawn(async move {
        run_tcp_listener(tcp_listener, tcp_state, tcp_sem).await;
    });

    let cert_path = std::env::var("CERT_PATH").unwrap_or_else(|_| "fullchain.pem".to_string());
    let key_path = std::env::var("KEY_PATH").unwrap_or_else(|_| "privkey.pem".to_string());
    let loaded_cert = tls::load_or_generate(&cert_path, &key_path)?;

    // DoT
    let dot_tls_config = tls::dot_server_config(&loaded_cert)?;
    let dot_acceptor = TlsAcceptor::from(dot_tls_config);
    let (dot_listener, active_dot_port) = bind_tcp(&host, requested_dot_port, 8853).await?;
    let dot_state = app_state.clone();
    let dot_sem = dot_semaphore.clone();
    tokio::spawn(async move {
        run_dot_listener(dot_listener, dot_acceptor, dot_state, dot_sem).await;
    });

    // DoQ
    let doq_server_config = create_quic_server_config(&loaded_cert, vec![b"doq".to_vec()])?;
    let (doq_endpoint, active_doq_port) =
        bind_quic_endpoint(&host, requested_doq_port, 8853, doq_server_config)?;
    let doq_state = app_state.clone();
    let doq_sem = doq_semaphore.clone();
    tokio::spawn(async move {
        run_doq_listener(doq_endpoint, doq_state, doq_sem).await;
    });

    // DoH3
    let doh3_server_config = create_quic_server_config(&loaded_cert, vec![b"h3".to_vec()])?;
    let (doh3_endpoint, active_doh3_port) =
        bind_quic_endpoint(&host, requested_doh3_port, 8443, doh3_server_config)?;
    let doh3_state = app_state.clone();
    let doh3_sem = doh3_semaphore.clone();
    tokio::spawn(async move {
        run_doh3_listener(doh3_endpoint, doh3_state, doh3_sem).await;
    });

    // DoH
    let (doh_test_sock, active_doh_port) = bind_tcp(&host, requested_doh_port, 8443).await?;
    drop(doh_test_sock);

    let doh_router = build_doh_router(app_state.clone());
    let doh_addr: std::net::SocketAddr = format!("{}:{}", host, active_doh_port).parse()?;
    let doh_handle = axum_server::Handle::new();
    let doh_handle_for_serve = doh_handle.clone();

    if doh_no_tls {
        tracing::info!(
            dns_port = active_dns_port,
            dot_port = active_dot_port,
            doq_port = active_doq_port,
            doh_port = active_doh_port,
            doh3_port = active_doh3_port,
            doh_mode = "plain HTTP",
            "[SERVER] All listeners active"
        );
        let listener = tokio::net::TcpListener::bind(doh_addr).await?;
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                doh_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
        });
    } else {
        tracing::info!(
            dns_port = active_dns_port,
            dot_port = active_dot_port,
            doq_port = active_doq_port,
            doh_port = active_doh_port,
            doh3_port = active_doh3_port,
            doh_mode = "HTTPS (TLS)",
            "[SERVER] All listeners active"
        );
        let doh_tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            loaded_cert.cert_file.clone(),
            loaded_cert.key_file.clone(),
        )
        .await?;

        tokio::spawn(async move {
            let _ = axum_server::bind_rustls(doh_addr, doh_tls_config)
                .handle(doh_handle_for_serve)
                .serve(doh_router.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await;
        });
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("[SERVER] Shutdown requested. Saving cache...");
            doh_handle.shutdown();
            save_cache_to_disk_async(cache.clone(), cache_file().to_string()).await;
            tracing::info!("[SERVER] Cache saved. Exiting cleanly.");
        }
    }

    Ok(())
}

async fn bind_udp(
    host: &str,
    preferred: u16,
    fallback: u16,
) -> Result<(UdpSocket, u16), std::io::Error> {
    let addr = format!("{}:{}", host, preferred);
    match UdpSocket::bind(&addr).await {
        Ok(s) => Ok((s, preferred)),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            tracing::warn!(
                preferred,
                fallback,
                "[UDP] Permission denied for port, using fallback"
            );
            let s = UdpSocket::bind(format!("{}:{}", host, fallback)).await?;
            Ok((s, fallback))
        }
        Err(e) => Err(e),
    }
}

async fn bind_tcp(
    host: &str,
    preferred: u16,
    fallback: u16,
) -> Result<(TcpListener, u16), std::io::Error> {
    let addr = format!("{}:{}", host, preferred);
    match TcpListener::bind(&addr).await {
        Ok(s) => Ok((s, preferred)),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            tracing::warn!(
                preferred,
                fallback,
                "[TCP] Permission denied for port, using fallback"
            );
            let s = TcpListener::bind(format!("{}:{}", host, fallback)).await?;
            Ok((s, fallback))
        }
        Err(e) => Err(e),
    }
}

async fn preload_domains(
    cache: DnsCache,
    recursor: Arc<RecursiveResolver>,
    domains: Vec<String>,
    concurrency: usize,
) {
    let total_domains = domains.len();
    if total_domains == 0 {
        return;
    }

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let warmed_count = Arc::new(AtomicUsize::new(0));
    let completed_domains = Arc::new(AtomicUsize::new(0));
    let start_time = Instant::now();

    for domain in domains {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };

        let cache_ref = cache.clone();
        let recursor_ref = recursor.clone();
        let warmed_ref = warmed_count.clone();
        let completed_ref = completed_domains.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let fqdn = if domain.ends_with('.') {
                domain.clone()
            } else {
                format!("{}.", domain)
            };

            if let Ok(name) = Name::from_str(&fqdn) {
                for qtype in [RecordType::A, RecordType::AAAA] {
                    let cache_key = format!("{}:{}:IN", name.to_ascii().to_lowercase(), qtype);
                    if cache_ref.contains_key(&cache_key) {
                        continue;
                    }

                    if let Ok(mut msg) = recursor_ref.resolve(&name, qtype).await {
                        if matches!(
                            msg.response_code(),
                            ResponseCode::NoError | ResponseCode::NXDomain
                        ) {
                            let status = dnssec::DnssecValidator::validate_message(
                                &recursor_ref,
                                &msg,
                                &name,
                                qtype,
                            )
                            .await;

                            if status == dnssec::DnssecStatus::Bogus
                                || status == dnssec::DnssecStatus::InsecureUnknown
                            {
                                continue;
                            }

                            let kind = if msg.response_code() == ResponseCode::NXDomain
                                || (msg.response_code() == ResponseCode::NoError
                                    && msg.answers().is_empty())
                            {
                                EntryKind::Negative
                            } else {
                                EntryKind::Positive
                            };

                            msg.set_id(0);
                            msg.set_authoritative(false);
                            msg.set_recursion_available(true);
                            msg.set_recursion_desired(false);
                            msg.set_checking_disabled(false);
                            msg.set_authentic_data(status == dnssec::DnssecStatus::Secure);

                            if let Ok(wire) = msg.to_bytes() {
                                let now = now_secs();
                                let ttl = calculate_cache_ttl(&msg, status, now);

                                if ttl > 0 {
                                    cache_ref.insert(
                                        cache_key,
                                        CacheEntry {
                                            raw_wire: wire,
                                            min_ttl: ttl,
                                            cached_at: now,
                                            last_revalidated_at: now,
                                            dnssec_status: status,
                                            kind,
                                        },
                                    );
                                    warmed_ref.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            }

            let done = completed_ref.fetch_add(1, Ordering::Relaxed) + 1;
            if done.is_multiple_of(50) || done == total_domains {
                tracing::info!(
                    progress = format!("{}/{}", done, total_domains),
                    records_cached = warmed_ref.load(Ordering::Relaxed),
                    "[WARM] Pre-warming progress"
                );
            }
        });
    }

    let _ = semaphore.acquire_many(concurrency as u32).await;
    tracing::info!(
        records_warmed = warmed_count.load(Ordering::Relaxed),
        elapsed_sec = start_time.elapsed().as_secs(),
        "[WARM] Pre-warming completed"
    );
}
