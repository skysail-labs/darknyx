//! In-TEE order book + matching loop. The matching ALGORITHM
//! itself lives in `darkpool-matcher` (single source of truth,
//! also used by litesvm parity tests). This module is the
//! integration layer: order intake, indexing, tick driver, hand-off
//! to the settle scheduler.
//!
//! See `docs/tee-architecture.md` §5.

pub mod book;
pub mod interval;
pub mod selftrade;
