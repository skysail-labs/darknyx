//! Where the prover writes its witness scratch (SW-14).
//!
//! Deliberately NOT inside `snarkjs`, which only compiles under the
//! `rapidsnark`/`icicle` features — neither of which builds without a native
//! library present. A guard whose tests only run in an environment nobody runs
//! locally is the same as no guard, so this lives where the default `cargo
//! nextest run --workspace` exercises it.

use std::path::PathBuf;

/// Where the witness scratch directory lives (SW-14).
///
/// `input.json` contains the **private witness**: every per-slot trade amount,
/// both counterparties' owner commitments, the change and fee amounts, and the
/// clearing price. Those are precisely the values amount-privacy (P1b/P3b) took
/// off-chain, and this wrote them to `std::env::temp_dir()` — `/tmp`, the
/// container's writable overlay, NOT the encrypted named volume the compose file
/// goes out of its way to provision for state.
///
/// The overlay is in fact encrypted at rest: `dstack/basefiles/dstack-prepare.sh`
/// bind-mounts Docker's data-root onto the LUKS-encrypted data disk, whose key
/// comes from dstack-kms. That is why this is Medium and not High. But "the disk
/// happens to be encrypted" is a property of the host image, established two
/// layers away from this function and easy to lose; the witness should not be on
/// a filesystem at all.
///
/// The witness generator is an external binary that takes PATHS, so the bytes
/// have to be somewhere. Order of preference:
///
/// 1. `DARKNYX_TEE_WITNESS_DIR` — an explicit operator choice (the compose now
///    mounts a `tmpfs` there).
/// 2. `/dev/shm` — tmpfs on any normal Linux, so the bytes stay in RAM, which
///    inside a TDX guest is encrypted by the CPU and never reaches storage.
/// 3. `std::env::temp_dir()` — the old behaviour, kept as a fallback so a
///    non-Linux dev box still works, and WARNED about so it is a choice rather
///    than a default.
///
/// Note on erasure: the cleanup removes the directory, but unlinking does not
/// reliably erase on a journaling or copy-on-write filesystem, so overwriting
/// before delete would be theatre. Keeping the bytes off disk in the first place
/// is the property worth having.
// Its only callers are the feature-gated backends, so in a default build it is
// genuinely unused — but the tests below must still run there, which is the
// whole reason this module is not itself gated. Scoped to exactly that
// configuration rather than a blanket allow, so a real dead-code regression in
// a rapidsnark/icicle build is still caught.
#[cfg_attr(not(any(feature = "rapidsnark", feature = "icicle")), allow(dead_code))]
pub(crate) fn witness_scratch_base() -> PathBuf {
    if let Some(explicit) = std::env::var_os("DARKNYX_TEE_WITNESS_DIR") {
        let p = PathBuf::from(explicit);
        if p.is_dir() {
            return p;
        }
        tracing::warn!(
            dir = %p.display(),
            "DARKNYX_TEE_WITNESS_DIR is not a directory; falling back"
        );
    }
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        return shm;
    }
    let tmp = std::env::temp_dir();
    tracing::warn!(
        dir = %tmp.display(),
        "no RAM-backed scratch dir available — the private match witness will be \
         written to a filesystem. Set DARKNYX_TEE_WITNESS_DIR to a tmpfs mount."
    );
    tmp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SW-14 — the witness must not default to a disk-backed `/tmp`.
    ///
    /// `input.json` carries the private witness (per-slot trade amounts, both
    /// owner commitments, the clearing price). It went to `std::env::temp_dir()`
    /// — the container's writable overlay, not the encrypted named volume the
    /// compose provisions for state.
    #[test]
    fn scratch_prefers_a_ram_backed_directory() {
        // On Linux `/dev/shm` is tmpfs, so the bytes stay in guest RAM — which
        // TDX encrypts in hardware — and never reach storage.
        let base = witness_scratch_base();
        if std::path::Path::new("/dev/shm").is_dir() {
            assert_eq!(
                base,
                std::path::PathBuf::from("/dev/shm"),
                "a RAM-backed scratch dir exists and must be preferred over temp_dir()"
            );
        } else {
            // macOS dev boxes have no /dev/shm; the fallback is intentional and
            // warned about. Assert only that it resolves to something usable,
            // so this test is meaningful on Linux and inert (not vacuous-looking)
            // elsewhere.
            assert!(base.is_dir(), "fallback scratch dir must exist");
        }
    }

    #[test]
    fn an_explicit_scratch_dir_wins() {
        // What the compose sets: `DARKNYX_TEE_WITNESS_DIR=/witness`, a tmpfs.
        let tmp = std::env::temp_dir().join("darknyx-scratch-test");
        std::fs::create_dir_all(&tmp).unwrap();
        // SAFETY: single-threaded test; no other thread reads the environment.
        unsafe { std::env::set_var("DARKNYX_TEE_WITNESS_DIR", &tmp) };
        let got = witness_scratch_base();
        unsafe { std::env::remove_var("DARKNYX_TEE_WITNESS_DIR") };
        std::fs::remove_dir_all(&tmp).ok();
        assert_eq!(got, tmp);
    }
}
