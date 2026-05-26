//! Boot-time dstack handshake.
//!
//! Phase-1: just verify the socket is reachable and log what
//! `info()` returns. Later phases will:
//!   - call `get_key("nyx/ed25519-signer/v1")` to derive our signer
//!   - cross-check the on-chain `vault_config.tee_pubkey` matches
//!   - export `/attestation` + `/info` endpoints
//!   - kick off the Merkle sync from VaultConfig.current_root
//!
//! See `docs/tee-architecture.md` §3 (boot sequence).

use anyhow::Result;

/// Probe `/var/run/dstack.sock` (or `DSTACK_SIMULATOR_ENDPOINT`)
/// and log what's there. Returns `Ok(())` even on failure during
/// Phase 1 — we want the skeleton to compile and run without a
/// real socket available.
pub async fn probe_dstack() -> Result<()> {
    match std::env::var("DSTACK_SIMULATOR_ENDPOINT") {
        Ok(path) => {
            tracing::info!(socket = %path, "dstack simulator detected");
        }
        Err(_) => {
            tracing::info!(
                "no DSTACK_SIMULATOR_ENDPOINT set — assuming /var/run/dstack.sock \
                 (only available inside a real CVM)"
            );
        }
    }

    // TODO(phase1): once the dstack-sdk dep is wired up properly,
    // call DstackClient::new(...).info() and log the result.
    // Keeping this as a no-op placeholder for now so the binary
    // builds standalone without needing the socket present.

    Ok(())
}
