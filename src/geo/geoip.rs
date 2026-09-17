// src/geo/geoip.rs
//
// MaxMind GeoLite2 lookup wrapper.
//
// If the database is missing or a lookup fails, the caller receives
// None and falls back to "unknown location" behavior in the router.

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;

pub struct GeoIpReader {
    reader: Reader<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct ClientLocation {
    pub country: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    /// Continent code (e.g. "EU", "AS"). Retained for Phase 2 scoring
    /// where continent-level routing may be more stable than country.
    #[allow(dead_code)]
    pub continent: Option<String>,
}

impl GeoIpReader {
    pub fn open(path: &Path) -> Result<Self, maxminddb::MaxMindDBError> {
        let reader = Reader::open_readfile(path)?;
        Ok(Self { reader })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<ClientLocation> {
        let city: geoip2::City = self.reader.lookup(ip).ok()?;

        let country = city
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string());

        let continent = city
            .continent
            .as_ref()
            .and_then(|c| c.code)
            .map(|s| s.to_string());

        let (latitude, longitude) = match city.location {
            Some(loc) => (loc.latitude, loc.longitude),
            None => (None, None),
        };

        Some(ClientLocation {
            country,
            continent,
            latitude,
            longitude,
        })
    }
}
