//! LUKS-encrypted disk snapshots — order book + Merkle leaves +
//! settle outbox. Disk encryption key is derived by dstack-kms
//! from the app root key, so snapshots survive CVM migration. See
//! `docs/tee-architecture.md` §8.

pub mod snapshot;
