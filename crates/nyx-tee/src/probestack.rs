//! Provide the `__rust_probestack` symbol on x86_64-linux.
//!
//! WHY THIS EXISTS
//! ---------------
//! The prover pulls in `wasmer` 4.4 (transitively via `ark-circom`, to
//! run the circom witness-generator wasm). `wasmer_vm` 4.4 has a
//! `probestack` module whose `PROBESTACK` static stores the address of
//! the `extern` symbol `__rust_probestack` — the wasm JIT wires that
//! function in as the stack-overflow probe for compiled guest code.
//!
//! `__rust_probestack` used to be exported by `compiler_builtins`, but
//! modern rustc (we are pinned to 1.91 via `rust-toolchain.toml`, and
//! cannot go lower — dstack-sdk → alloy → ruint requires 1.91+) switched
//! to *inline* stack probes and no longer emits or exports the symbol.
//! So linking the nyx-tee binary (or its test binaries) for
//! x86_64-unknown-linux-gnu fails with:
//!
//!     undefined reference to `__rust_probestack'
//!         in wasmer_vm::libcalls::function_pointer
//!         (.data.rel.ro.wasmer_vm_probestack)
//!
//! It only surfaced when the binary was first built for x86_64-linux
//! (the Phala CVM target) — the dev Macs are arm64-darwin, which has no
//! probestack intrinsic. We can't bump out of it: ark-circom 0.5.0 (the
//! latest) pins `wasmer ^4.4` + `wasmer-wasix ^0.28`, and the probestack
//! reference is present across all of wasmer 4.x (removed only in 5.x+).
//!
//! THE FIX
//! -------
//! Re-supply the symbol ourselves: the canonical x86_64 page-touching
//! routine that `compiler_builtins` used to ship. It probes (faults-in)
//! every page of a requested stack frame (size passed in `%rax`) without
//! permanently moving `%rsp`, so a deep wasm call frame trips the guard
//! page instead of silently running off the stack. Declared `.weak` so
//! that if a future toolchain (or a wasmer bump) ever provides a strong
//! definition again, that one wins and we don't get a duplicate-symbol
//! link error.
//!
//! Gated to `target_arch = "x86_64", target_os = "linux"` — the only
//! place the reference exists for us (the deploy target + the amd64 CI
//! runners). aarch64-darwin builds reference no such symbol and skip
//! this entirely.
//!
//! See also memory `tee_binary_amd64_link` and deploy/Dockerfile.

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
core::arch::global_asm!(
    ".text",
    ".weak __rust_probestack",
    ".type __rust_probestack,@function",
    "__rust_probestack:",
    ".cfi_startproc",
    "pushq %rbp",
    ".cfi_adjust_cfa_offset 8",
    ".cfi_offset %rbp, -16",
    "movq %rsp, %rbp",
    ".cfi_def_cfa_register %rbp",
    // %rax holds the requested frame size; keep a working copy in %r11.
    "mov %rax,%r11",
    // If the frame is at most one page, skip straight to the remainder.
    "cmp $0x1000,%r11",
    "jna 3f",
    // Touch one page at a time so each guard page is hit in order.
    "2:",
    "sub $0x1000,%rsp",
    "test %rsp,8(%rsp)",
    "sub $0x1000,%r11",
    "cmp $0x1000,%r11",
    "ja 2b",
    // Probe the final sub-page remainder.
    "3:",
    "sub %r11,%rsp",
    "test %rsp,8(%rsp)",
    // Undo the probing subtractions (leave restores via %rbp anyway, but
    // keep the CFI/stack state matching the canonical routine).
    "add %rax,%rsp",
    "leave",
    ".cfi_def_cfa_register %rsp",
    ".cfi_adjust_cfa_offset -8",
    "ret",
    ".cfi_endproc",
    ".size __rust_probestack, . - __rust_probestack",
    // The routine above is AT&T syntax (`%reg`, `$imm`); Rust's
    // global_asm! defaults to Intel, so declare the dialect explicitly.
    options(att_syntax),
);
