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

const ERR_CAP: usize = 1024;

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
        let mut handle: *mut c_void = std::ptr::null_mut();
        let mut err = [0 as c_char; ERR_CAP];
        let rc = unsafe {
            groth16_prover_create(
                &mut handle,
                zkey.as_ptr() as *const c_void,
                zkey.len() as u64,
                err.as_mut_ptr(),
                ERR_CAP as u64,
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
        // Size the proof buffer from rapidsnark; the public-signals JSON for a
        // two public inputs are tiny, so a generous fixed buffer suffices (we
        // still grow on SHORT_BUFFER to be safe).
        let mut proof_cap: u64 = 0;
        unsafe { groth16_proof_size(&mut proof_cap) };
        let mut proof_cap = (proof_cap as usize).max(2048);
        let mut public_cap: usize = 8192;

        loop {
            let mut proof_buf = vec![0 as c_char; proof_cap];
            let mut public_buf = vec![0 as c_char; public_cap];
            let mut proof_len = proof_cap as u64;
            let mut public_len = public_cap as u64;
            let mut err = [0 as c_char; ERR_CAP];

            let rc = unsafe {
                groth16_prover_prove(
                    self.handle,
                    wtns.as_ptr() as *const c_void,
                    wtns.len() as u64,
                    proof_buf.as_mut_ptr(),
                    &mut proof_len,
                    public_buf.as_mut_ptr(),
                    &mut public_len,
                    err.as_mut_ptr(),
                    ERR_CAP as u64,
                )
            };

            match rc {
                PROVER_OK => {
                    let proof = c_chars_to_string(&proof_buf, proof_len as usize);
                    let public = c_chars_to_string(&public_buf, public_len as usize);
                    return Ok((proof, public));
                }
                PROVER_ERROR_SHORT_BUFFER => {
                    // rapidsnark wrote the required sizes back into the lengths.
                    proof_cap = (proof_len as usize).max(proof_cap + 1);
                    public_cap = (public_len as usize).max(public_cap + 1);
                    continue;
                }
                _ => {
                    return Err(format!(
                        "groth16_prover_prove rc={rc}: {}",
                        err_string(&err)
                    ))
                }
            }
        }
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
    let n = len.min(buf.len());
    let bytes: Vec<u8> = buf[..n].iter().map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
