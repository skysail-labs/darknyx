//! Minimal safe FFI over rapidsnark's `extern "C"` prover API (src/prover.h).
//! Only compiled with the `rapidsnark` feature; the static libs are linked by
//! build.rs from `$RAPIDSNARK_LIB_DIR`.
//!
//! Lifecycle: create ONE prover from the zkey at boot (parses + precomputes),
//! then `prove(&wtns)` per batch. The prover object is an opaque C handle; we
//! wrap it so callers serialize access (the settle worker proves one batch at a
//! time, and the higher-level `RapidsnarkMatchBatchProver` guards it behind a
//! Mutex).

use std::ffi::{c_char, c_void};

// prover.h return codes.
const PROVER_OK: i32 = 0;
const PROVER_ERROR_SHORT_BUFFER: i32 = 2;

#[allow(non_snake_case)]
extern "C" {
    // We use the BUFFER variant (not `_zkey_file`): rapidsnark's
    // `groth16_prover_create_zkey_file` loads the zkey into a LOCAL FileLoader
    // and hands `Groth16Prover` a BinFile that only REFERENCES (never copies)
    // that buffer — so the buffer is freed on return and `prove` dereferences
    // dangling memory (SIGBUS). With the buffer variant the CALLER owns the
    // zkey bytes; we keep them alive in `RawProver` for its whole lifetime.
    fn groth16_prover_create(
        prover_object: *mut *mut c_void,
        zkey_buffer: *const c_void,
        zkey_size: u64,
        error_msg: *mut c_char,
        error_msg_maxsize: u64,
    ) -> i32;

    fn groth16_prover_prove(
        prover_object: *mut c_void,
        wtns_buffer: *const c_void,
        wtns_size: u64,
        proof_buffer: *mut c_char,
        proof_size: *mut u64,
        public_buffer: *mut c_char,
        public_size: *mut u64,
        error_msg: *mut c_char,
        error_msg_maxsize: u64,
    ) -> i32;

    fn groth16_proof_size(proof_size: *mut u64);

    fn groth16_prover_destroy(prover_object: *mut c_void);
}

/// The native boundary is deliberately small and fixed. Groth16 proof/public
/// JSON for the supported circuits is far below these ceilings; the limits are
/// guardrails against a broken or hostile library reporting absurd required
/// lengths on `SHORT_BUFFER`.
const ERROR_BUFFER_CAPACITY: usize = 1024;
const INITIAL_PROOF_CAPACITY: usize = 2048;
const INITIAL_PUBLIC_CAPACITY: usize = 8192;
const MAX_PROOF_CAPACITY: usize = 64 * 1024;
const MAX_PUBLIC_CAPACITY: usize = 64 * 1024;
const MAX_PROVE_ATTEMPTS: usize = 3;

#[derive(Clone, Copy, Debug)]
struct NativeProveResult {
    code: i32,
    proof_len: u64,
    public_len: u64,
}

fn err_string(buf: &[c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Opaque rapidsnark prover handle + the zkey bytes it references. `Send` so it
/// can live in the worker's `Arc<dyn Prover>`; NOT `Sync` — concurrent `prove`
/// on one handle is serialized by a Mutex in the caller.
pub struct RawProver {
    handle: *mut c_void,
    /// The zkey bytes the C `Groth16Prover` REFERENCES (rapidsnark's BinFile
    /// does not copy). Must outlive `handle`; kept here so the prover's
    /// section pointers stay valid for the process lifetime. The heap buffer
    /// doesn't move when `RawProver` is moved (into the Mutex/Arc).
    _zkey: Vec<u8>,
}

// SAFETY: the handle is only ever used from one thread at a time (the caller
// guards it with a Mutex). The pointer itself is movable across threads.
unsafe impl Send for RawProver {}

impl RawProver {
    /// Create the prover from a `circuit_final.zkey` file: read the bytes into
    /// an owned buffer (kept alive for the prover's lifetime) and hand them to
    /// the buffer-variant create (parses + precomputes once; reuse for every
    /// prove). See the extern comment for why the file variant is unsafe.
    pub fn create_from_zkey_file(zkey_path: &str) -> Result<Self, String> {
        let zkey = std::fs::read(zkey_path).map_err(|e| format!("read zkey {zkey_path}: {e}"))?;
        let zkey_len =
            u64::try_from(zkey.len()).map_err(|_| "zkey length does not fit u64".to_string())?;
        let mut handle: *mut c_void = std::ptr::null_mut();
        let mut err = [0 as c_char; ERROR_BUFFER_CAPACITY];
        let rc = unsafe {
            groth16_prover_create(
                &mut handle,
                zkey.as_ptr() as *const c_void,
                zkey_len,
                err.as_mut_ptr(),
                ERROR_BUFFER_CAPACITY as u64,
            )
        };
        if rc != PROVER_OK || handle.is_null() {
            return Err(format!(
                "groth16_prover_create rc={rc}: {}",
                err_string(&err)
            ));
        }
        Ok(Self {
            handle,
            _zkey: zkey,
        })
    }

    /// Prove an in-memory `.wtns` witness buffer. Returns the snarkjs-format
    /// `(proof_json, public_json)` strings.
    pub fn prove(&self, wtns: &[u8]) -> Result<(String, String), String> {
        let mut proof_size_hint = 0;
        unsafe { groth16_proof_size(&mut proof_size_hint) };
        let wtns_len =
            u64::try_from(wtns.len()).map_err(|_| "witness length does not fit u64".to_string())?;

        bounded_prove(proof_size_hint, |proof_buf, public_buf, err| {
            let mut proof_len = proof_buf.len() as u64;
            let mut public_len = public_buf.len() as u64;
            let code = unsafe {
                groth16_prover_prove(
                    self.handle,
                    wtns.as_ptr() as *const c_void,
                    wtns_len,
                    proof_buf.as_mut_ptr(),
                    &mut proof_len,
                    public_buf.as_mut_ptr(),
                    &mut public_len,
                    err.as_mut_ptr(),
                    ERROR_BUFFER_CAPACITY as u64,
                )
            };
            NativeProveResult {
                code,
                proof_len,
                public_len,
            }
        })
    }
}

impl Drop for RawProver {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { groth16_prover_destroy(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

fn c_chars_to_string(buf: &[c_char], len: usize) -> String {
    let bytes: Vec<u8> = buf[..len].iter().map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn bounded_prove<F>(proof_size_hint: u64, mut invoke: F) -> Result<(String, String), String>
where
    F: FnMut(&mut [c_char], &mut [c_char], &mut [c_char]) -> NativeProveResult,
{
    let proof_size_hint = checked_usize("proof size hint", proof_size_hint)?;
    let mut proof_cap = proof_size_hint.max(INITIAL_PROOF_CAPACITY);
    if proof_cap > MAX_PROOF_CAPACITY {
        return Err(format!(
            "rapidsnark proof size hint {proof_cap} exceeds maximum {MAX_PROOF_CAPACITY}"
        ));
    }
    let mut public_cap = INITIAL_PUBLIC_CAPACITY;

    for attempt in 1..=MAX_PROVE_ATTEMPTS {
        let mut proof_buf = vec![0 as c_char; proof_cap];
        let mut public_buf = vec![0 as c_char; public_cap];
        let mut err = [0 as c_char; ERROR_BUFFER_CAPACITY];
        let result = invoke(&mut proof_buf, &mut public_buf, &mut err);

        match result.code {
            PROVER_OK => {
                let proof_len = checked_output_len("proof", result.proof_len, proof_buf.len())?;
                let public_len =
                    checked_output_len("public signals", result.public_len, public_buf.len())?;
                return Ok((
                    c_chars_to_string(&proof_buf, proof_len),
                    c_chars_to_string(&public_buf, public_len),
                ));
            }
            PROVER_ERROR_SHORT_BUFFER => {
                if attempt == MAX_PROVE_ATTEMPTS {
                    return Err(format!(
                        "groth16_prover_prove returned SHORT_BUFFER after \
                         {MAX_PROVE_ATTEMPTS} attempts"
                    ));
                }

                let next_proof = checked_required_capacity(
                    "proof",
                    result.proof_len,
                    proof_cap,
                    MAX_PROOF_CAPACITY,
                )?;
                let next_public = checked_required_capacity(
                    "public signals",
                    result.public_len,
                    public_cap,
                    MAX_PUBLIC_CAPACITY,
                )?;
                if next_proof == proof_cap && next_public == public_cap {
                    return Err(
                        "groth16_prover_prove returned SHORT_BUFFER without a larger required size"
                            .to_string(),
                    );
                }
                proof_cap = next_proof;
                public_cap = next_public;
            }
            code => {
                return Err(format!(
                    "groth16_prover_prove rc={code}: {}",
                    err_string(&err)
                ));
            }
        }
    }

    unreachable!("bounded prove loop returns on success, error, or retry exhaustion")
}

fn checked_usize(label: &str, value: u64) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("rapidsnark {label} {value} does not fit usize"))
}

fn checked_output_len(label: &str, value: u64, capacity: usize) -> Result<usize, String> {
    let value = checked_usize(label, value)?;
    if value > capacity {
        return Err(format!(
            "rapidsnark reported {label} length {value} beyond buffer capacity {capacity}"
        ));
    }
    Ok(value)
}

fn checked_required_capacity(
    label: &str,
    value: u64,
    current: usize,
    maximum: usize,
) -> Result<usize, String> {
    let value = checked_usize(label, value)?;
    if value > maximum {
        return Err(format!(
            "rapidsnark required {label} capacity {value} exceeds maximum {maximum}"
        ));
    }
    Ok(current.max(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_chars(buf: &mut [c_char], value: &str) {
        assert!(value.len() <= buf.len());
        for (dst, src) in buf.iter_mut().zip(value.bytes()) {
            *dst = src as c_char;
        }
    }

    #[test]
    fn bounded_prove_succeeds_without_retry() {
        let mut calls = 0;
        let (proof, public) = bounded_prove(512, |proof_buf, public_buf, err| {
            calls += 1;
            assert_eq!(proof_buf.len(), INITIAL_PROOF_CAPACITY);
            assert_eq!(public_buf.len(), INITIAL_PUBLIC_CAPACITY);
            assert_eq!(err.len(), ERROR_BUFFER_CAPACITY);
            write_chars(proof_buf, "proof");
            write_chars(public_buf, "[\"1\"]");
            NativeProveResult {
                code: PROVER_OK,
                proof_len: 5,
                public_len: 5,
            }
        })
        .unwrap();

        assert_eq!(calls, 1);
        assert_eq!(proof, "proof");
        assert_eq!(public, "[\"1\"]");
    }

    #[test]
    fn bounded_prove_grows_only_the_reported_short_buffer() {
        let mut capacities = Vec::new();
        let result = bounded_prove(512, |proof_buf, public_buf, _| {
            capacities.push((proof_buf.len(), public_buf.len()));
            if capacities.len() == 1 {
                NativeProveResult {
                    code: PROVER_ERROR_SHORT_BUFFER,
                    proof_len: 4096,
                    public_len: public_buf.len() as u64,
                }
            } else {
                write_chars(proof_buf, "ok");
                write_chars(public_buf, "[]");
                NativeProveResult {
                    code: PROVER_OK,
                    proof_len: 2,
                    public_len: 2,
                }
            }
        })
        .unwrap();

        assert_eq!(result, ("ok".to_string(), "[]".to_string()));
        assert_eq!(
            capacities,
            vec![
                (INITIAL_PROOF_CAPACITY, INITIAL_PUBLIC_CAPACITY),
                (4096, INITIAL_PUBLIC_CAPACITY)
            ]
        );
    }

    #[test]
    fn bounded_prove_rejects_short_buffer_without_progress() {
        let mut calls = 0;
        let err = bounded_prove(512, |proof_buf, public_buf, _| {
            calls += 1;
            NativeProveResult {
                code: PROVER_ERROR_SHORT_BUFFER,
                proof_len: proof_buf.len() as u64,
                public_len: public_buf.len() as u64,
            }
        })
        .unwrap_err();

        assert_eq!(calls, 1);
        assert!(err.contains("without a larger required size"));
    }

    #[test]
    fn bounded_prove_rejects_hostile_size_before_allocating_it() {
        let mut capacities = Vec::new();
        let err = bounded_prove(512, |proof_buf, public_buf, _| {
            capacities.push((proof_buf.len(), public_buf.len()));
            NativeProveResult {
                code: PROVER_ERROR_SHORT_BUFFER,
                proof_len: u64::MAX,
                public_len: public_buf.len() as u64,
            }
        })
        .unwrap_err();

        assert_eq!(
            capacities,
            vec![(INITIAL_PROOF_CAPACITY, INITIAL_PUBLIC_CAPACITY)]
        );
        assert!(err.contains("exceeds maximum") || err.contains("does not fit usize"));
    }

    #[test]
    fn bounded_prove_stops_after_three_attempts() {
        let mut capacities = Vec::new();
        let err = bounded_prove(512, |proof_buf, public_buf, _| {
            capacities.push((proof_buf.len(), public_buf.len()));
            NativeProveResult {
                code: PROVER_ERROR_SHORT_BUFFER,
                proof_len: (proof_buf.len() + 1) as u64,
                public_len: public_buf.len() as u64,
            }
        })
        .unwrap_err();

        assert_eq!(
            capacities,
            vec![
                (INITIAL_PROOF_CAPACITY, INITIAL_PUBLIC_CAPACITY),
                (INITIAL_PROOF_CAPACITY + 1, INITIAL_PUBLIC_CAPACITY),
                (INITIAL_PROOF_CAPACITY + 2, INITIAL_PUBLIC_CAPACITY),
            ]
        );
        assert!(err.contains("after 3 attempts"));
    }

    #[test]
    fn bounded_prove_rejects_excessive_initial_hint_without_calling_native() {
        let mut called = false;
        let err = bounded_prove((MAX_PROOF_CAPACITY + 1) as u64, |_, _, _| {
            called = true;
            unreachable!()
        })
        .unwrap_err();

        assert!(!called);
        assert!(err.contains("proof size hint"));
        assert!(err.contains("exceeds maximum"));
    }

    #[test]
    fn bounded_prove_rejects_success_length_beyond_buffer() {
        let err = bounded_prove(512, |proof_buf, public_buf, _| NativeProveResult {
            code: PROVER_OK,
            proof_len: (proof_buf.len() + 1) as u64,
            public_len: public_buf.len() as u64,
        })
        .unwrap_err();

        assert!(err.contains("beyond buffer capacity"));
    }

    #[test]
    fn bounded_prove_preserves_native_error() {
        let err = bounded_prove(512, |_, _, err| {
            write_chars(err, "native failure");
            NativeProveResult {
                code: 7,
                proof_len: 0,
                public_len: 0,
            }
        })
        .unwrap_err();

        assert!(err.contains("rc=7"));
        assert!(err.contains("native failure"));
    }
}
