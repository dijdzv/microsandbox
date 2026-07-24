//! TLS interception configuration types.
//!
//! These types configure inline TLS MITM for the smoltcp networking stack.
//! All TCP connections terminate at smoltcp, so TLS interception is handled
//! directly by proxy tasks — no kernel redirect rules needed.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::policy::{DomainName, DomainNameError};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// TLS interception configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Whether TLS interception is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// TCP ports subject to TLS interception (default: `[443]`).
    #[serde(default = "default_intercepted_ports")]
    pub intercepted_ports: Vec<u16>,

    /// Domains to bypass (no MITM). Supports exact match and `*.suffix` wildcards.
    #[serde(default)]
    pub bypass: Vec<String>,

    /// Exact TLS hostnames redirected to a host loopback listener.
    ///
    /// Only the port is configurable. The destination address is always
    /// `127.0.0.1`, so this cannot become an arbitrary host-side proxy.
    #[serde(default)]
    pub loopback_routes: TlsLoopbackRoutes,

    /// Whether to verify the upstream server's TLS certificate.
    #[serde(default = "default_true")]
    pub verify_upstream: bool,

    /// Drop UDP to intercepted ports when TLS interception is active,
    /// forcing QUIC traffic to fall back to TCP/TLS.
    #[serde(default = "default_true")]
    pub block_quic_on_intercept: bool,

    /// CA certificate PEM files to trust for upstream server verification.
    #[serde(default)]
    pub upstream_ca_cert: Vec<PathBuf>,

    /// Host-scoped CA certificate PEM files to trust for upstream server verification.
    #[serde(default, alias = "scoped_upstream_ca_certs")]
    pub scoped_upstream_ca_cert: Vec<ScopedUpstreamCaCert>,

    /// Host-scoped upstream verification overrides.
    #[serde(default)]
    pub scoped_verify_upstream: Vec<ScopedVerifyUpstream>,

    /// Interception CA configuration. The TLS proxy uses this CA to sign
    /// per-domain certs that it presents to the guest during interception.
    #[serde(default, alias = "ca")]
    pub intercept_ca: InterceptCaConfig,

    /// Per-domain certificate cache configuration.
    #[serde(default)]
    pub cache: CertCacheConfig,
}

/// A CA certificate PEM file trusted only for matching upstream hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedUpstreamCaCert {
    /// Host pattern this CA applies to. Supports exact hosts and `*.suffix` wildcards.
    pub pattern: String,

    /// Path to the CA certificate PEM file.
    pub path: PathBuf,
}

/// An upstream certificate verification override for matching hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedVerifyUpstream {
    /// Host pattern this override applies to. Supports exact hosts and `*.suffix` wildcards.
    pub pattern: String,

    /// Whether to verify matching upstream server certificates.
    pub verify: bool,
}

/// Exact TLS hostname routes to host loopback listeners.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TlsLoopbackRoutes(BTreeMap<TlsLoopbackHost, NonZeroU16>);

/// A validated exact hostname for a host-loopback TLS route.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TlsLoopbackHost(DomainName);

/// Errors reported when a TLS loopback route host is not exact.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TlsLoopbackHostError {
    /// The hostname is not a valid DNS name.
    #[error(transparent)]
    InvalidDomain(#[from] DomainNameError),

    /// Wildcards would make a loopback route broader than one exact hostname.
    #[error("TLS loopback route host must not contain a wildcard")]
    Wildcard,
}

/// Certificate authority configuration for TLS interception.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterceptCaConfig {
    /// Path to an existing CA certificate PEM file.
    /// If `None`, a CA is auto-generated and persisted.
    #[serde(default)]
    pub cert_path: Option<PathBuf>,

    /// Path to an existing CA private key PEM file.
    /// If `None`, a key is auto-generated and persisted.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

/// Per-domain certificate cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertCacheConfig {
    /// Maximum number of cached certificates. Default: 1000.
    #[serde(default = "default_cache_capacity")]
    pub capacity: usize,

    /// Certificate validity duration in hours. Default: 24.
    #[serde(default = "default_cert_validity_hours")]
    pub validity_hours: u64,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            intercepted_ports: default_intercepted_ports(),
            bypass: Vec::new(),
            loopback_routes: TlsLoopbackRoutes::default(),
            verify_upstream: true,
            block_quic_on_intercept: true,
            upstream_ca_cert: Vec::new(),
            scoped_upstream_ca_cert: Vec::new(),
            scoped_verify_upstream: Vec::new(),
            intercept_ca: InterceptCaConfig::default(),
            cache: CertCacheConfig::default(),
        }
    }
}

impl Default for CertCacheConfig {
    fn default() -> Self {
        Self {
            capacity: default_cache_capacity(),
            validity_hours: default_cert_validity_hours(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TlsLoopbackRoutes {
    /// Add or replace the loopback port for one exact, validated hostname.
    pub fn insert(&mut self, host: TlsLoopbackHost, port: NonZeroU16) {
        self.0.insert(host, port);
    }

    /// Resolve an exact SNI hostname to the fixed host-loopback destination.
    pub fn target(&self, host: &str) -> Option<SocketAddr> {
        let host = host.parse::<TlsLoopbackHost>().ok()?;
        self.0
            .get(&host)
            .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port.get()))
    }
}

impl std::str::FromStr for TlsLoopbackHost {
    type Err = TlsLoopbackHostError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::try_from(raw.to_owned())
    }
}

impl TryFrom<String> for TlsLoopbackHost {
    type Error = TlsLoopbackHostError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        if raw.contains('*') {
            return Err(TlsLoopbackHostError::Wildcard);
        }
        Ok(Self(raw.parse()?))
    }
}

impl From<TlsLoopbackHost> for String {
    fn from(host: TlsLoopbackHost) -> Self {
        host.0.as_str().to_owned()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_intercepted_ports() -> Vec<u16> {
    vec![443]
}

fn default_cache_capacity() -> usize {
    1000
}

fn default_cert_validity_hours() -> u64 {
    24
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::num::NonZeroU16;

    use super::*;

    #[test]
    fn loopback_routes_match_only_the_exact_canonical_host() {
        let mut routes = TlsLoopbackRoutes::default();
        routes.insert(
            "LLM-BROKER.ORBIT.INVALID."
                .parse()
                .expect("valid exact host"),
            NonZeroU16::new(43123).expect("non-zero port"),
        );

        assert_eq!(
            routes.target("llm-broker.orbit.invalid"),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43123))
        );
        assert_eq!(
            routes.target("LLM-BROKER.ORBIT.INVALID."),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43123))
        );
        assert_eq!(routes.target("other.llm-broker.orbit.invalid"), None);
    }

    #[test]
    fn loopback_routes_deserialize_validated_hosts_and_nonzero_ports() {
        let config: TlsConfig = serde_json::from_str(
            r#"{
                "loopback_routes": {
                    "llm-broker.orbit.invalid": 43123
                }
            }"#,
        )
        .expect("valid loopback route");

        assert_eq!(
            config.loopback_routes.target("llm-broker.orbit.invalid"),
            Some("127.0.0.1:43123".parse().expect("socket address"))
        );

        assert!(
            serde_json::from_str::<TlsConfig>(r#"{"loopback_routes":{"*.orbit.invalid":43123}}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<TlsConfig>(
                r#"{"loopback_routes":{"llm-broker.orbit.invalid":0}}"#
            )
            .is_err()
        );
    }
}
