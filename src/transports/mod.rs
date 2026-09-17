// src/transports/mod.rs
pub mod doh;
pub mod doh3;
pub mod doq;
pub mod dot;
pub mod metrics_handler;
pub mod quic;
pub mod tcp;
pub mod udp;

pub use doh::build_doh_router;
pub use doh3::run_doh3_listener;
pub use doq::run_doq_listener;
pub use dot::run_dot_listener;
pub use tcp::run_tcp_listener;
pub use udp::run_udp_listener;
