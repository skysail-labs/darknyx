//! MatchResultPayload construction. Borsh shape MUST match
//! `programs/vault/src/instructions/tee_forced_settle.rs::MatchResultPayload`
//! byte-for-byte. The fixed-vector test in vault pins the on-chain
//! side; the SDK's settle-builder-batched test pins TS. This file
//! is the third leg of that contract.
