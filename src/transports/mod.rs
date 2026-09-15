// src/transports/mod.rs
pub mod doh;
pub mod dot;
pub mod tcp;
pub mod udp;

pub use doh::build_doh_router;
pub use dot::run_dot_listener;
pub use tcp::run_tcp_listener;
pub use udp::run_udp_listener;
