//! Boot-selected oracle source and its fixed safety policy.
//!
//! The source is deliberately an enum rather than a collection of independent
//! booleans: exactly one producer owns the cache in a process.  A deployment
//! cannot accidentally run the slow push-feed freshness window while claiming
//! to use the low-latency router path.

use std::str::FromStr;
use std::time::Duration;

use super::cache::FreshnessPolicy;

pub const ROUTER_MAX_AGE_MS: u64 = 5_000;
pub const SOLANA_PUSH_MAX_AGE_MS: u64 = 90_000;
pub const MAX_ORACLE_FUTURE_SKEW_MS: u64 = 1_000;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum OracleMode {
    PythRouterQuorumV1,
    /// Development default. Mainnet release policy must explicitly select and
    /// client-pin the low-latency router mode.
    #[default]
    PythSolanaPushV1,
}

impl OracleMode {
    pub const ROUTER_NAME: &'static str = "pyth-router-quorum-v1";
    pub const SOLANA_PUSH_NAME: &'static str = "pyth-solana-push-v1";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PythRouterQuorumV1 => Self::ROUTER_NAME,
            Self::PythSolanaPushV1 => Self::SOLANA_PUSH_NAME,
        }
    }

    pub const fn freshness(self) -> FreshnessPolicy {
        FreshnessPolicy {
            max_age_ms: match self {
                Self::PythRouterQuorumV1 => ROUTER_MAX_AGE_MS,
                Self::PythSolanaPushV1 => SOLANA_PUSH_MAX_AGE_MS,
            },
            max_future_skew_ms: MAX_ORACLE_FUTURE_SKEW_MS,
        }
    }

    pub const fn refresh_interval(self) -> Duration {
        match self {
            Self::PythRouterQuorumV1 => Duration::from_secs(1),
            Self::PythSolanaPushV1 => Duration::from_secs(2),
        }
    }

    pub const fn source_kind(self) -> OracleSourceKind {
        match self {
            Self::PythRouterQuorumV1 => OracleSourceKind::PythRouterQuorumV1,
            Self::PythSolanaPushV1 => OracleSourceKind::PythSolanaPushV1,
        }
    }
}

impl FromStr for OracleMode {
    type Err = OracleModeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            Self::ROUTER_NAME => Ok(Self::PythRouterQuorumV1),
            Self::SOLANA_PUSH_NAME => Ok(Self::PythSolanaPushV1),
            other => Err(OracleModeParseError(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown oracle mode {0:?}; expected pyth-router-quorum-v1 or pyth-solana-push-v1")]
pub struct OracleModeParseError(String);

/// Authentication provenance stored alongside every cached update.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OracleSourceKind {
    PythRouterQuorumV1,
    PythSolanaPushV1,
    DebugFixtureV1,
}

impl OracleSourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PythRouterQuorumV1 => OracleMode::ROUTER_NAME,
            Self::PythSolanaPushV1 => OracleMode::SOLANA_PUSH_NAME,
            Self::DebugFixtureV1 => "debug-fixture-v1",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_are_strict_versioned_and_have_distinct_freshness() {
        assert_eq!(
            OracleMode::ROUTER_NAME.parse::<OracleMode>().unwrap(),
            OracleMode::PythRouterQuorumV1
        );
        assert_eq!(
            OracleMode::SOLANA_PUSH_NAME.parse::<OracleMode>().unwrap(),
            OracleMode::PythSolanaPushV1
        );
        assert!("solana-push".parse::<OracleMode>().is_err());
        assert_eq!(OracleMode::PythRouterQuorumV1.freshness().max_age_ms, 5_000);
        assert_eq!(OracleMode::PythSolanaPushV1.freshness().max_age_ms, 90_000);
    }
}
