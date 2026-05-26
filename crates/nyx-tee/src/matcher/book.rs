//! Per-market in-memory book. Phase 1: stub. Phase 2: BTreeMap<Price,
//! FifoQueue<OrderId>> + auxiliary indices as described in
//! `docs/tee-architecture.md` §5.1.
//!
//! Reads share state with `crate::merkle` and `crate::api::tree`
//! via `Arc<RwLock<...>>` — see `docs/tee-architecture.md` §5.5.
