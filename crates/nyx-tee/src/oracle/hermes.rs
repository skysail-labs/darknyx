//! Hermes HTTPS client. Talks to `hermes.pyth.network` (or a
//! configurable mirror) and returns parsed price updates ready
//! for the VAA verifier.
//!
//! Endpoint shape (Hermes v2 API):
//!
//! ```text
//! GET https://hermes.pyth.network/v2/updates/price/latest
//!     ?ids[]=<feed_id_hex>
//!     [&ids[]=<another_feed_id>]
//! ```
//!
//! Response:
//!
//! ```json
//! {
//!   "binary": {
//!     "encoding": "hex",
//!     "data": ["010000000001005..."]  ← VAA bytes, hex-encoded
//!   },
//!   "parsed": [
//!     {
//!       "id": "ef0d8b6f...",
//!       "price":     { "price": "12345678", "conf": "100", "expo": -8, "publish_time": 1700000000 },
//!       "ema_price": { "price": "12345555", "conf": "100", "expo": -8, "publish_time": 1700000000 }
//!     }
//!   ]
//! }
//! ```
//!
//! We use `ema_price` as the TWAP — same convention as the
//! on-chain `read_oracle_price` reader (it pulls `ema_price` out of
//! `PriceUpdateV2`).

use anyhow::Result;
use serde::Deserialize;
use std::time::Duration;

/// Default Hermes endpoint. Override via `HermesClient::with_endpoint`
/// if we need to point at hermes-beta.pyth.network or a
/// self-hosted mirror.
pub const DEFAULT_HERMES_ENDPOINT: &str = "https://hermes.pyth.network";

#[derive(Debug, thiserror::Error)]
pub enum HermesError {
    #[error("HTTP request to {url} failed: {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("Hermes returned HTTP {status} for {url}: {body}")]
    Status {
        url: String,
        status: u16,
        body: String,
    },
    #[error("Hermes response JSON parse failed for {url}: {source}")]
    Json {
        url: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("Hermes returned no parsed price for feed {feed_id}")]
    MissingParsed { feed_id: String },
    #[error("Hermes returned no VAA binary data for feed {feed_id}")]
    MissingVaa { feed_id: String },
    #[error("invalid hex in Hermes VAA binary: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("Pyth EMA price was non-positive ({0}) — refusing to cache")]
    NonPositivePrice(i64),
}

#[derive(Debug, Clone)]
pub struct HermesPriceUpdate {
    pub feed_id: String,
    /// EMA price as u64. Pyth itself returns it as i64 — we reject
    /// non-positive values at parse time (a defensive check that
    /// matches the on-chain `OracleNegativePrice` error).
    pub ema_price: u64,
    pub confidence: u64,
    pub exponent: i32,
    pub publish_time_ms: u64,
    /// Decoded VAA bytes from `binary.data[0]`. Passed straight to
    /// `vaa::verify(...)` by the caller.
    pub vaa: Vec<u8>,
}

#[derive(Clone)]
pub struct HermesClient {
    endpoint: String,
    http: reqwest::Client,
}

impl HermesClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_endpoint(DEFAULT_HERMES_ENDPOINT)
    }

    pub fn with_endpoint(endpoint: &str) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            // Reasonable timeouts. Hermes responds in 10-200 ms typically;
            // 5 s is generous enough for slow network days.
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("nyx-tee/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Fetch the latest price + VAA for a single feed id (hex).
    pub async fn fetch(&self, feed_id: &str) -> Result<HermesPriceUpdate, HermesError> {
        let url = format!(
            "{}/v2/updates/price/latest?ids[]={}",
            self.endpoint, feed_id
        );

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|source| HermesError::Http {
                url: url.clone(),
                source,
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(HermesError::Status {
                url: url.clone(),
                status: status.as_u16(),
                body,
            });
        }

        let body = resp.text().await.map_err(|source| HermesError::Http {
            url: url.clone(),
            source,
        })?;
        let parsed: RawResponse =
            serde_json::from_str(&body).map_err(|source| HermesError::Json {
                url: url.clone(),
                source,
            })?;

        // Extract the VAA bytes from the AccumulatorUpdateData
        // wrapper. Hermes returns hex strings in `binary.data[]`;
        // we take the first one (single-feed queries have one VAA).
        let accum_hex =
            parsed
                .binary
                .data
                .into_iter()
                .next()
                .ok_or_else(|| HermesError::MissingVaa {
                    feed_id: feed_id.to_string(),
                })?;
        let accum_bytes = hex::decode(accum_hex)?;

        // Hermes returns Pyth's `AccumulatorUpdateData` wrapper,
        // not a raw VAA. Strip the wrapper to extract just the
        // VAA bytes for `vaa::verify`. The Merkle update payload
        // after the VAA is not consumed in v2 (we trust the
        // `parsed[]` price); a future v3 path would also Merkle-
        // verify each price feed against the VAA's attested root.
        let vaa = extract_vaa_from_accumulator(&accum_bytes, feed_id)?;

        // Find the parsed entry for our feed.
        let raw_entry = parsed
            .parsed
            .into_iter()
            .find(|p| p.id.eq_ignore_ascii_case(feed_id))
            .ok_or_else(|| HermesError::MissingParsed {
                feed_id: feed_id.to_string(),
            })?;

        // Pyth's `price` field is a string-encoded i64 ("Pyth-native"
        // fixed point per `expo`). The EMA shares the same scaling.
        let raw_price: i64 = raw_entry
            .ema_price
            .price
            .parse()
            .map_err(|_| HermesError::Json {
                url: url.clone(),
                source: serde::de::Error::custom("ema_price.price not a valid i64"),
            })?;
        if raw_price <= 0 {
            return Err(HermesError::NonPositivePrice(raw_price));
        }
        // Fail on a malformed confidence the same way `price` does,
        // rather than silently substituting 0 — `conf` feeds the
        // VALID_PRICE binding work, so a quiet zero would corrupt it.
        let raw_conf: u64 = raw_entry
            .ema_price
            .conf
            .parse()
            .map_err(|_| HermesError::Json {
                url: url.clone(),
                source: serde::de::Error::custom("ema_price.conf not a valid u64"),
            })?;

        Ok(HermesPriceUpdate {
            feed_id: raw_entry.id,
            ema_price: raw_price as u64,
            confidence: raw_conf,
            exponent: raw_entry.ema_price.expo,
            // Hermes returns publish_time as seconds; convert to ms.
            publish_time_ms: raw_entry.ema_price.publish_time * 1000,
            vaa,
        })
    }
}

// ─────── Wire types (private — only used to deserialize Hermes JSON) ────────

#[derive(Debug, Deserialize)]
struct RawResponse {
    binary: RawBinary,
    parsed: Vec<RawParsedEntry>,
}

#[derive(Debug, Deserialize)]
struct RawBinary {
    #[allow(dead_code)]
    encoding: String,
    data: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawParsedEntry {
    id: String,
    ema_price: RawPrice,
    // We don't currently consume `price` (the spot price) — Pyth's
    // EMA is what the on-chain reader also uses, so we mirror that.
    // Keeping the field absent from the struct = serde ignores it.
}

#[derive(Debug, Deserialize)]
struct RawPrice {
    price: String,
    conf: String,
    expo: i32,
    publish_time: u64,
}

// ─────── Pyth AccumulatorUpdateData wrapper extraction ──────────────────────
//
// Hermes returns each `binary.data[]` entry as Pyth's
// `AccumulatorUpdateData` envelope, not a raw VAA. Layout:
//
// ```text
//   bytes 0-3   magic                ("PNAU" = 0x504e4155)
//   byte  4     major_version        (1)
//   byte  5     minor_version        (0)
//   byte  6     trailing_header_size (currently 0; skip that many bytes)
//   byte  7     proof_type           (0 = WormholeMerkle)
//   bytes 8-9   vaa_length (BE u16)
//   bytes 10..  vaa
//   ...         num_updates + updates[] (Merkle proofs — v2 ignores)
// ```
//
// Source: https://github.com/pyth-network/pyth-crosschain/blob/main/pythnet/pythnet_sdk/src/wire.rs::AccumulatorUpdateData
//
// We extract just the VAA bytes and discard the Merkle update
// section — that section is what a v3 on-chain verifier would
// consume to bind a specific price feed to the attested Merkle
// root. v2 trusts the `parsed[]` Hermes response for the price.

const ACCUM_MAGIC: &[u8; 4] = b"PNAU";

fn extract_vaa_from_accumulator(bytes: &[u8], feed_id: &str) -> Result<Vec<u8>, HermesError> {
    if bytes.len() < 10 || &bytes[0..4] != ACCUM_MAGIC {
        return Err(HermesError::Json {
            url: format!("(extracting VAA for feed {feed_id})"),
            source: serde::de::Error::custom(
                "Hermes binary.data is not an AccumulatorUpdateData (missing 'PNAU' magic)",
            ),
        });
    }
    // bytes[4]: major, bytes[5]: minor, bytes[6]: trailing_header_size,
    // bytes[7]: proof_type. We accept any major/minor for now (Pyth has
    // stayed at 1.0); reject any proof_type other than WormholeMerkle (0).
    if bytes[7] != 0 {
        return Err(HermesError::Json {
            url: format!("(extracting VAA for feed {feed_id})"),
            source: serde::de::Error::custom(format!(
                "unsupported AccumulatorUpdateData proof_type {} (expected 0 = WormholeMerkle)",
                bytes[7]
            )),
        });
    }
    let trailing = bytes[6] as usize;
    let vaa_len_offset = 8 + trailing;
    if bytes.len() < vaa_len_offset + 2 {
        return Err(HermesError::Json {
            url: format!("(extracting VAA for feed {feed_id})"),
            source: serde::de::Error::custom("AccumulatorUpdateData truncated at vaa_length"),
        });
    }
    let vaa_len = u16::from_be_bytes([bytes[vaa_len_offset], bytes[vaa_len_offset + 1]]) as usize;
    let vaa_start = vaa_len_offset + 2;
    let vaa_end = vaa_start + vaa_len;
    if bytes.len() < vaa_end {
        return Err(HermesError::Json {
            url: format!("(extracting VAA for feed {feed_id})"),
            source: serde::de::Error::custom(format!(
                "AccumulatorUpdateData declares VAA of {vaa_len} bytes but buffer is only {} bytes long",
                bytes.len() - vaa_start
            )),
        });
    }
    Ok(bytes[vaa_start..vaa_end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_vaa_from_fixture() {
        let bytes = include_bytes!("../../tests/fixtures/sol_usd_vaa.bin");
        let vaa = extract_vaa_from_accumulator(bytes, "sol_usd").expect("extract");
        // Sanity: VAA starts with version=1.
        assert_eq!(vaa[0], 1, "VAA version byte");
        // The captured fixture is signed against set 6 (per
        // vaa::MAINNET_GUARDIAN_SET_INDEX). Its second-through-
        // fifth bytes encode the guardian_set_index BE u32.
        assert_eq!(&vaa[1..5], &[0, 0, 0, 6], "guardian_set_index");
    }

    #[test]
    fn rejects_non_pnau_magic() {
        let bad = vec![0xde, 0xad, 0xbe, 0xef, 1, 0, 0, 0, 0, 0];
        assert!(extract_vaa_from_accumulator(&bad, "test").is_err());
    }
}
