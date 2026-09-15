// src/engine/mod.rs
pub mod limits;
pub mod query;
pub mod resolve;
pub mod response;

pub use resolve::{process_dns_query, AppState, ProcessOutcome};
pub use response::calculate_cache_ttl;
