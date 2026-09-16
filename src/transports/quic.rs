// src/transports/quic.rs
use crate::tls::LoadedCert;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub fn create_quic_server_config(
    loaded: &LoadedCert,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<quinn::ServerConfig, Box<dyn std::error::Error>> {
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(loaded.certs.clone(), loaded.key.clone_key())
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    crypto.alpn_protocols = alpn_protocols;

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    if let Ok(timeout) = Duration::from_secs(10).try_into() {
        transport.max_idle_timeout(Some(timeout));
    }
    transport.keep_alive_interval(Some(Duration::from_secs(3)));
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

pub fn bind_quic_endpoint(
    host: &str,
    preferred: u16,
    fallback: u16,
    config: quinn::ServerConfig,
) -> Result<(quinn::Endpoint, u16), Box<dyn std::error::Error>> {
    let addr: SocketAddr = format!("{}:{}", host, preferred).parse()?;
    match quinn::Endpoint::server(config.clone(), addr) {
        Ok(ep) => Ok((ep, preferred)),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let fallback_addr: SocketAddr = format!("{}:{}", host, fallback).parse()?;
            tracing::warn!(
                preferred,
                fallback,
                "[QUIC] Permission denied for port, using fallback"
            );
            let ep = quinn::Endpoint::server(config, fallback_addr)?;
            Ok((ep, fallback))
        }
        Err(e) => Err(e.into()),
    }
}
