//! `GET /transport-attestation?nonce=<64 hex chars>` — a fresh TDX quote that
//! binds the **served TLS certificate** to this enclave, this boot, and this
//! signer set (T-03P).
//!
//! # Why this is not `/attestation`
//!
//! `/attestation` proves an enclave with a given signer set is alive. It does
//! not tell you that the TLS connection carrying your orders terminates there.
//! A party able to terminate TLS relays a genuine `/attestation` response and
//! routes your traffic somewhere else — the cuckoo-proxy problem. Closing it
//! needs the certificate's public key inside the attested value.
//!
//! The two endpoints coexist. `dstack.get_quote` takes caller-selected
//! `report_data` on **every** call, so this mints its own quote under its own
//! domain tag and **`/attestation` is unchanged byte-for-byte**. (An earlier
//! audit record claimed RA-TLS forced a breaking migration of `/attestation`;
//! that was wrong — see `audits/audit_6/tracker.md`.)
//!
//! # The contract
//!
//! ```text
//! report_data[0..32]  = the caller's nonce, exactly 32 bytes
//! report_data[32..64] = SHA-256(DOMAIN ‖ canonical_manifest_bytes)
//! ```
//!
//! Every field of the manifest is taken from **server state** — the in-memory
//! SPKI, the current `boot_session_id`, the current full signer set. None of it
//! is read from the request. A caller supplies exactly one thing, the nonce,
//! and it only ever lands in the left half. That is the whole input surface.
//!
//! # Unauthenticated by necessity
//!
//! A client must verify the transport *before* it sends a credential, so this
//! route cannot require one. It is therefore the one pre-auth surface that
//! performs a TDX quote, which is expensive — hence the rate limit below.
//! Nothing here is secret: the manifest, the quote, and the event log are all
//! values a client is meant to check against public governance.
//!
//! Failure modes:
//!   - RA-TLS identity not initialised (legacy/plaintext mode) → 503
//!   - dstack socket unreachable (degraded boot)               → 503
//!   - `nonce` missing, non-hex, or not exactly 32 bytes       → 400
//!   - rate limit exceeded                                      → 429
//!   - `get_quote` fails                                        → 500

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use super::state::ApiState;
use crate::transport::{TransportManifest, TransportMode};

/// Quote generation is not cheap and this route is pre-auth. The window is
/// per-process, not per-caller: a legitimate client needs one call per
/// connection, so a low global ceiling is generous for real use and hostile to
/// a flood. Deliberately not per-IP — behind the dstack gateway every request
/// shares a source address, so per-IP buckets would be security theatre here.
/// Bound on the unauthenticated `dstack.get_quote` call.
///
/// Generous relative to a healthy quote (~100 ms locally, ~1.5 s through the
/// gateway) because the cost of being too tight is a spurious 503 on a route
/// clients must succeed on before they can do anything else.
const QUOTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);
const RATE_LIMIT_PER_WINDOW: u32 = 20;

/// Fixed-WINDOW counter over 1 second — deliberately not a token bucket.
///
/// The distinction is behavioural, not pedantic: the window hard-resets, so a
/// client can spend the whole allowance at the end of one window and the whole
/// allowance at the start of the next, admitting up to 2x the ceiling across a
/// boundary. A token bucket would smooth that. This is acceptable here because
/// the ceiling exists to bound TDX quote work, not to enforce a precise rate,
/// and 2x a deliberately generous bound is still bounded — but the comment
/// used to say "token bucket", which described burst behaviour the code does
/// not have.
#[derive(Debug)]
pub struct TransportAttestationRateLimiter {
    inner: Mutex<RateWindow>,
}

#[derive(Debug)]
struct RateWindow {
    window_start: Instant,
    count: u32,
}

impl Default for TransportAttestationRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportAttestationRateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RateWindow {
                window_start: Instant::now(),
                count: 0,
            }),
        }
    }

    /// `true` if this request is admitted.
    pub fn admit(&self, now: Instant) -> bool {
        let mut w = match self.inner.lock() {
            Ok(g) => g,
            // A poisoned lock means a previous holder panicked. Fail closed:
            // refuse the request rather than bypass the limiter.
            Err(_) => return false,
        };
        if now.duration_since(w.window_start) >= RATE_LIMIT_WINDOW {
            w.window_start = now;
            w.count = 0;
        }
        if w.count >= RATE_LIMIT_PER_WINDOW {
            return false;
        }
        w.count += 1;
        true
    }
}

#[derive(Debug, Deserialize)]
pub struct TransportAttestationParams {
    /// Hex-encoded caller nonce. Exactly 32 bytes (64 hex characters).
    pub nonce: Option<String>,
}

/// The manifest, rendered for the wire. Field names mirror
/// `packages/sdk/src/tee/transport-manifest.ts` so a client can rebuild the
/// canonical bytes and recompute the digest itself — which is the point: these
/// values are *claims* until the client recomputes them and matches the quote.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TransportManifestWire {
    pub protocol_version: u16,
    /// `"ra-tls"` or `"gateway-terminated"`.
    pub transport_mode: &'static str,
    /// Hex `SHA-256(app_id)`.
    pub app_id_sha256: String,
    /// Hex `SHA-256(instance_id)`.
    pub instance_id_sha256: String,
    pub boot_session_id: String,
    /// Hex `SHA-256` of the DER SubjectPublicKeyInfo of the served certificate.
    /// **A client MUST compare this against the certificate on the socket it is
    /// actually using** — not a separate probe connection.
    pub tls_spki_sha256: String,
    pub signer_set_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct TransportAttestationResponse {
    pub manifest: TransportManifestWire,
    /// Hex-encoded TDX quote over `report_data`.
    pub quote: String,
    /// dstack event log as a JSON string. Replay against the DCAP-verified
    /// quote's RTMR3 to recover the measured compose hash. The compose hash is
    /// deliberately **not** a manifest field — here it is verifiable, there it
    /// would be a self-report.
    pub event_log: String,
    /// Hex of the 64-byte `report_data` embedded in the quote.
    pub report_data: String,
    /// Domain tag the digest was computed under, so a client can fail loudly on
    /// a version it does not implement rather than silently mis-verify.
    pub domain: String,
}

fn mode_str(mode: TransportMode) -> &'static str {
    match mode {
        TransportMode::RaTls => "ra-tls",
        TransportMode::GatewayTerminated => "gateway-terminated",
    }
}

pub async fn handler(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<TransportAttestationParams>,
) -> Result<Json<TransportAttestationResponse>, super::error::ApiError> {
    // 1. Validate the caller's input BEFORE charging the limiter.
    //
    //    The limiter used to be charged first, on the reasoning that a flood
    //    should cost a mutex rather than a TDX round-trip. That is right about
    //    quote cost and wrong about availability: parsing 64 hex characters is
    //    cheaper still, so charging before it let a flood of `?nonce=zz`
    //    consume the entire global allowance and deny honest clients the ONE
    //    pre-auth call they must make before they can do anything else. A
    //    malformed request now costs the attacker a 400 and costs the budget
    //    nothing.
    //
    //    Order matters, and getting it backwards was a real defect caught by
    //    `nonce_hex_is_checked_before_the_identity_is_required` and
    //    `nonce_length_is_checked_before_the_identity_is_required`: a client
    //    that sends a malformed nonce should be told its request is wrong
    //    (400), not that the service is down (503). Validating first is also
    //    the cheaper path and avoids disclosing whether RA-TLS is enabled to a
    //    caller who has not even sent a well-formed request.
    //
    //    Exactly 32 bytes — no padding. A caller who sends 4 bytes and believes
    //    it has 32 bytes of replay protection is wrong in a way zero-padding
    //    would conceal. Errors never echo the caller's input back: this route
    //    is pre-auth, and a reflection gadget here is free to deny.
    let nonce_hex = params.nonce.unwrap_or_default();
    if nonce_hex.is_empty() {
        return Err(super::error::ApiError::malformed(
            "nonce is required and must be 32 bytes of hex (64 characters)".to_string(),
        ));
    }
    let nonce = hex::decode(&nonce_hex).map_err(|_| {
        super::error::ApiError::malformed(
            "nonce is not valid hex; expected 64 hex characters".to_string(),
        )
    })?;
    if nonce.len() != 32 {
        return Err(super::error::ApiError::malformed(format!(
            "nonce must be exactly 32 bytes, got {}",
            nonce.len()
        )));
    }

    // 2. Charge the limiter now that the request is known well-formed. From
    //    here on the work is genuinely expensive (a TDX quote), which is what
    //    the budget exists to protect.
    if !state.transport_rate_limiter.admit(Instant::now()) {
        return Err(super::error::ApiError::from((
            StatusCode::TOO_MANY_REQUESTS,
            "transport attestation rate limit exceeded".to_string(),
        )));
    }

    // 3. Only now look at service state. In legacy/plaintext mode there is no
    //    served certificate of ours to bind, and inventing one would be worse
    //    than saying so.
    let identity = state.transport_identity.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "RA-TLS transport is not enabled on this instance".to_string(),
        )
    })?;

    let dstack = state.dstack.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "dstack socket not reachable; transport attestation unavailable".to_string(),
        )
    })?;

    // 4. Build the manifest from SERVER state only. Nothing below is
    //    caller-influenced; that is what makes the binding meaningful.
    let manifest = TransportManifest::new(
        TransportMode::RaTls,
        state.app_info.app_id.as_bytes(),
        state.app_info.instance_id.as_bytes(),
        state.boot_session_id,
        identity.spki_sha256(),
        state.signer_set_hash,
    );

    let report_data = manifest.report_data(&nonce).map_err(|e| {
        // Unreachable: the length is checked above. Handled rather than
        // unwrapped so a future edit to the check cannot turn into a panic on
        // an unauthenticated route.
        super::error::ApiError::malformed(e.to_string())
    })?;

    // 5. Mint the quote.
    // The dstack client has no default timeout, and this route is
    // unauthenticated. Without a bound, a hung socket pins an admitted handler
    // task indefinitely — the rate limiter caps admissions per second, not
    // concurrency or lifetime, so a stalled backend converts a bounded request
    // rate into unbounded retained tasks.
    let quote = tokio::time::timeout(QUOTE_TIMEOUT, dstack.get_quote(report_data.to_vec()))
        .await
        .map_err(|_| {
            tracing::error!("transport attestation: dstack get_quote timed out");
            super::error::ApiError::from((
                StatusCode::SERVICE_UNAVAILABLE,
                "attestation backend timed out".to_string(),
            ))
        })?
        .map_err(|e| {
            tracing::error!(error = %e, "transport attestation: dstack get_quote failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            )
        })?;

    Ok(Json(TransportAttestationResponse {
        manifest: TransportManifestWire {
            protocol_version: manifest.protocol_version,
            transport_mode: mode_str(manifest.transport_mode),
            app_id_sha256: hex::encode(manifest.app_id_sha256),
            instance_id_sha256: hex::encode(manifest.instance_id_sha256),
            boot_session_id: hex::encode(manifest.boot_session_id),
            tls_spki_sha256: hex::encode(manifest.tls_spki_sha256),
            signer_set_sha256: hex::encode(manifest.signer_set_sha256),
        },
        quote: quote.quote,
        event_log: quote.event_log,
        report_data: hex::encode(report_data),
        domain: String::from_utf8_lossy(crate::transport::DOMAIN).into_owned(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_admits_up_to_the_ceiling_then_refuses() {
        let rl = TransportAttestationRateLimiter::new();
        let t0 = Instant::now();
        for i in 0..RATE_LIMIT_PER_WINDOW {
            assert!(rl.admit(t0), "request {i} inside the ceiling was refused");
        }
        assert!(
            !rl.admit(t0),
            "the request past the ceiling was admitted — the limiter is inert"
        );
    }

    #[test]
    fn rate_limiter_resets_on_the_next_window() {
        let rl = TransportAttestationRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..RATE_LIMIT_PER_WINDOW {
            assert!(rl.admit(t0));
        }
        assert!(!rl.admit(t0));
        let t1 = t0 + RATE_LIMIT_WINDOW + Duration::from_millis(1);
        assert!(rl.admit(t1), "a new window did not reset the bucket");
    }

    #[test]
    fn rate_limiter_does_not_reset_early() {
        // Guards the boundary: a limiter that resets on any clock movement
        // would pass the two tests above while enforcing nothing.
        let rl = TransportAttestationRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..RATE_LIMIT_PER_WINDOW {
            assert!(rl.admit(t0));
        }
        let just_inside = t0 + RATE_LIMIT_WINDOW - Duration::from_millis(1);
        assert!(
            !rl.admit(just_inside),
            "the bucket reset before the window elapsed"
        );
    }

    #[test]
    fn mode_strings_are_stable_wire_values() {
        // These land in a JSON body a client matches on. Renaming one is a
        // wire break, so pin them.
        assert_eq!(mode_str(TransportMode::RaTls), "ra-tls");
        assert_eq!(
            mode_str(TransportMode::GatewayTerminated),
            "gateway-terminated"
        );
    }
}
