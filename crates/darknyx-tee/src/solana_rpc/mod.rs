//! Hand-rolled Solana JSON-RPC client.
//!
//! The enclave does not use `solana-client`, because it would pull a `zeroize`
//! major that conflicts with the `ark-ec` 0.5 already present transitively through
//! `darkpool-crypto`. Instead this module builds on `reqwest` for transport (the
//! same client and TLS configuration `oracle/hermes.rs` uses) and the modular
//! Solana crates — `solana-address`, `solana-hash`, `solana-keypair`,
//! `solana-signature`, `solana-signer` — for the type system. `programs/vault`'s
//! dev-dependencies use that same combination alongside the same `ark-*` crates, so
//! the pairing is proven elsewhere in the workspace.
//!
//! Implemented methods — the settle pipeline's needs, plus the reads the Merkle
//! mirror and recovery paths use:
//!
//! ```text
//!   getLatestBlockhash            recent_blockhash for every tx
//!   sendTransaction               submit signed bytes
//!   getSignatureStatuses          poll for confirmation
//!   getAccountInfo                read account state
//!   simulateTransaction           pre-flight before send
//!   getRecentPrioritizationFees   priority-fee bidding hints
//!   getMultipleAccounts           batched account reads
//!   getSignaturesForAddress       transaction discovery for the mirror
//!   getTransaction                decoding leaf-append events
//!   getTransactionsForAddress     batched variant of the above
//! ```
//!
//! ```text
//!   client.rs         transport, retries, and the methods above
//!   error.rs          the error type, with endpoint redaction
//!   vault_config.rs   parsing VaultConfig
//!   market_config.rs  parsing MarketConfig
//! ```
//!
//! **Errors from this module must never carry the endpoint URL.** The configured
//! URL contains the RPC provider's API key, and settle failures are surfaced
//! through a client-pollable status endpoint; `redact_endpoint` exists for that
//! reason (audit SW-01). A newly added error variant that formats the raw URL
//! reintroduces the leak.
//!
//! Note that `getHealth` is unauthenticated on some providers and answers 200 for a
//! revoked key, so it cannot be used to validate credentials — probe with
//! `getSlot` or `getVersion`, which return `-32401` on a dead key.

pub mod client;
pub mod error;
pub mod market_config;
pub mod vault_config;

pub use client::redact_endpoint;
pub use client::{
    AddressTxPage, BlockhashWithSlot, Commitment, PrioritizationFee, RpcAccountInfo,
    RpcAccountsWithContext, RpcAddressTx, RpcInstruction, RpcSignatureInfo, RpcSignatureStatus,
    RpcSimulationResult, RpcTransaction, SolanaRpcClient, TxSortOrder, MAX_MULTIPLE_ACCOUNTS,
};
pub use error::RpcError;
