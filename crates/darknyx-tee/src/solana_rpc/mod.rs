//! Hand-rolled Solana JSON-RPC client.
//!
//! Sidesteps `solana-client` 1.18 (which would pull a `zeroize`
//! major that conflicts with `ark-ec` 0.5 transitively present
//! via `darkpool-crypto`). Instead we use:
//!
//!   - `reqwest` for HTTP transport (already in tree for
//!     `oracle/hermes.rs` — same pattern, same TLS config).
//!   - The modular Solana 2.x/3.x crates (`solana-address`,
//!     `solana-hash`, `solana-keypair`, `solana-signature`,
//!     `solana-signer`) for the type system. `programs/vault`'s
//!     dev-deps already use this exact set alongside the same
//!     `ark-*` deps — so the compatibility is proven by an
//!     existing crate in the workspace.
//!
//! Scope of PR 4g.2: the 6 RPC methods the settle scheduler
//! needs across PRs 4g.3–4g.6:
//!
//!   - `getLatestBlockhash`           (every tx — for `recent_blockhash`)
//!   - `sendTransaction`              (submit signed bytes)
//!   - `getSignatureStatuses`         (poll for confirmation)
//!   - `getAccountInfo`               (read state, e.g. ALT slot)
//!   - `simulateTransaction`          (pre-flight before send)
//!   - `getRecentPrioritizationFees`  (priority-fee bidding hints)
//!
//! Higher-level helpers (`confirm_signature_with_timeout`,
//! `send_and_confirm`) land in later sub-PRs as call-sites need
//! them. This module is the bottom-of-stack primitive layer.

pub mod client;
pub mod error;
pub mod market_config;
pub mod vault_config;

pub use client::redact_endpoint;
pub use client::{
    AddressTxPage, BlockhashWithSlot, Commitment, PrioritizationFee, RpcAccountInfo, RpcAddressTx,
    RpcInstruction, RpcSignatureInfo, RpcSignatureStatus, RpcSimulationResult, RpcTransaction,
    SolanaRpcClient, TxSortOrder, MAX_MULTIPLE_ACCOUNTS,
};
pub use error::RpcError;
