//! Rolling Address Lookup Table pool for the settle worker.
//!
//! Each batch's settle tx (Tx D) hoists 7 derivable per-batch PDAs
//! (`note_lock_a/b/e/f` + `consumed_a/b` + `batch_validity_marker`) into an ALT
//! to stay under the 1232-byte cap. The naive approach — create a throwaway ALT
//! per batch — burns a `create` tx + rent every batch and never reclaims
//! it. This pool instead keeps a **long-lived `current` ALT** and just
//! `extend`s it with each batch's 7 addresses, rotating to a fresh ALT
//! (and deactivating the old one) only when it nears Solana's 256-address
//! cap.
//!
//! **What this does NOT remove:** the per-batch ~1-slot activation wait.
//! Newly *extended* addresses (not just newly *created* ALTs) are
//! unusable until the slot after the extend lands, and a batch's PDAs are
//! derived from that batch's own notes — so they can't be pre-loaded.
//! The worker still waits one slot after the extend/create before sending
//! Tx D. The pool's win is eliminating per-batch ALT *creation* + rent
//! churn and never blocking on the 512-slot deactivation cooldown.
//!
//! This module holds the pool **state + pure planning logic** only (so it
//! is unit-testable without RPC). The worker owns the RPC orchestration
//! (submit/confirm/slot-wait) and feeds outcomes back via `commit_*`.

use solana_address::Address;
use solana_message::AddressLookupTableAccount;

/// Soft cap on addresses per ALT before the pool rotates to a fresh one.
/// Solana's HARD cap is 256 addresses/ALT; we rotate at 246 for a
/// deliberate 10-slot slack (not an arbitrary number). That slack (a)
/// guarantees a worst-case 7-address single match can always be appended
/// without crossing 256 mid-batch — rotation happens BEFORE the extend,
/// never part-way through one — and (b) leaves headroom for a modest
/// future batch-size bump (e.g. two small batches, or a few extra
/// derivable PDAs per match) without re-tuning the cap.
pub const MAX_ALT_ENTRIES: usize = 246;

/// The currently-active ALT plus the full, ordered list of addresses
/// extended into it. The list MUST mirror the on-chain ALT's contents
/// exactly and in order — Tx D's v0 message encodes 1-byte *indices* into
/// it, and the runtime resolves those against the real on-chain ALT. A
/// divergence would silently map an index to the wrong account.
#[derive(Debug, Clone)]
struct ActiveAlt {
    address: Address,
    addresses: Vec<Address>,
}

/// What on-chain action a batch needs before it can settle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AltPlan {
    /// No usable `current` ALT (cold start, or rotation triggered) —
    /// create a fresh one and extend it with this batch's addresses.
    /// `deactivate` names the old `current` to deactivate on rotation
    /// (`None` on cold start).
    Create { deactivate: Option<Address> },
    /// `current` has room — extend it with this batch's addresses.
    Extend { alt: Address },
}

/// A two-slot rolling ALT pool: one active `current`, plus a list of
/// deactivated ALTs awaiting their 512-slot cooldown for rent reclaim.
#[derive(Debug, Default)]
pub struct AltPool {
    current: Option<ActiveAlt>,
    /// ALTs marked for deactivation, with the slot they were deactivated
    /// at. Rent is reclaimable ~512 slots later (a future sweep closes
    /// them). Kept here so the backlog is observable + bounded.
    cooling: Vec<(Address, u64)>,
}

impl AltPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide what this batch needs. Pure — does not mutate. Call the
    /// matching `commit_*` after the on-chain tx confirms.
    pub fn plan(&self, n_addrs: usize) -> AltPlan {
        match &self.current {
            Some(cur) if cur.addresses.len() + n_addrs <= MAX_ALT_ENTRIES => {
                AltPlan::Extend { alt: cur.address }
            }
            Some(cur) => AltPlan::Create {
                deactivate: Some(cur.address),
            },
            None => AltPlan::Create { deactivate: None },
        }
    }

    /// Record a freshly created+extended ALT as the new `current`. If
    /// `deactivated` is set (rotation), the old ALT is moved to the
    /// cooling list.
    pub fn commit_create(
        &mut self,
        alt: Address,
        addresses: Vec<Address>,
        deactivated: Option<(Address, u64)>,
    ) {
        if let Some((old, slot)) = deactivated {
            self.cooling.push((old, slot));
        }
        self.current = Some(ActiveAlt {
            address: alt,
            addresses,
        });
    }

    /// Append a confirmed extend's addresses to `current`.
    pub fn commit_extend(&mut self, addresses: &[Address]) {
        if let Some(cur) = self.current.as_mut() {
            cur.addresses.extend_from_slice(addresses);
        }
    }

    /// The `AddressLookupTableAccount` (key + full ordered address list)
    /// to stack in Tx D's v0 message. `None` before any batch has run.
    pub fn settle_account(&self) -> Option<AddressLookupTableAccount> {
        self.current.as_ref().map(|cur| AddressLookupTableAccount {
            key: cur.address,
            addresses: cur.addresses.clone(),
        })
    }

    /// The current ALT's address (key), if any. The worker captures this while
    /// holding the pool lock, then (after releasing) re-reads the ALT's
    /// canonical on-chain address order for the Tx D v0 message — its in-memory
    /// `addresses` order may not match once extends are fired concurrently.
    pub fn current_alt_address(&self) -> Option<Address> {
        self.current.as_ref().map(|c| c.address)
    }

    /// Number of entries in the current ALT (for logging / metrics).
    pub fn current_len(&self) -> usize {
        self.current
            .as_ref()
            .map(|c| c.addresses.len())
            .unwrap_or(0)
    }

    /// Count of ALTs awaiting rent reclaim (for logging / metrics).
    pub fn cooling_len(&self) -> usize {
        self.cooling.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::new_from_array([b; 32])
    }

    #[test]
    fn cold_start_plans_create_without_deactivate() {
        let pool = AltPool::new();
        assert_eq!(pool.plan(5), AltPlan::Create { deactivate: None });
        assert!(pool.settle_account().is_none());
    }

    #[test]
    fn extends_current_until_near_cap_then_rotates() {
        let mut pool = AltPool::new();
        // Cold start → create.
        assert_eq!(pool.plan(5), AltPlan::Create { deactivate: None });
        let first = addr(0x01);
        pool.commit_create(first, vec![addr(0xAA); 5], None);
        assert_eq!(pool.current_len(), 5);

        // Subsequent batches extend the same ALT.
        for _ in 0..10 {
            assert_eq!(pool.plan(5), AltPlan::Extend { alt: first });
            pool.commit_extend(&[addr(0xBB); 5]);
        }
        assert_eq!(pool.current_len(), 55);

        // Drive it right up to the soft cap, then expect a rotation that
        // deactivates the (now-full) current ALT.
        while pool.current_len() + 5 <= MAX_ALT_ENTRIES {
            pool.commit_extend(&[addr(0xCC); 5]);
        }
        assert!(pool.current_len() + 5 > MAX_ALT_ENTRIES);
        assert_eq!(
            pool.plan(5),
            AltPlan::Create {
                deactivate: Some(first)
            }
        );

        // Rotate: the old ALT goes to cooling, the new one becomes current.
        let second = addr(0x02);
        pool.commit_create(second, vec![addr(0xDD); 5], Some((first, 1000)));
        assert_eq!(pool.cooling_len(), 1);
        assert_eq!(pool.current_len(), 5);
        assert_eq!(pool.plan(5), AltPlan::Extend { alt: second });
    }

    #[test]
    fn settle_account_mirrors_current_contents() {
        let mut pool = AltPool::new();
        let alt = addr(0x07);
        pool.commit_create(alt, vec![addr(0x10), addr(0x11)], None);
        pool.commit_extend(&[addr(0x12)]);
        let acct = pool.settle_account().expect("current set");
        assert_eq!(acct.key, alt);
        assert_eq!(acct.addresses, vec![addr(0x10), addr(0x11), addr(0x12)]);
    }
}
