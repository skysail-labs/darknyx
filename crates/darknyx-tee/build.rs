//! Link the prebuilt static rapidsnark libraries when the `rapidsnark`
//! feature is on. A no-op otherwise — default builds (incl. local macOS
//! dev without the feature) link nothing new and need no C toolchain.
//!
//! We do NOT compile rapidsnark here — its C++/asm + gmp build is multi-minute
//! and belongs in a cached Docker layer / a one-off `make`, not in every
//! `cargo build`. build.rs just points the linker at the already-built static
//! libs via env:
//!
//!   RAPIDSNARK_LIB_DIR      dir holding librapidsnark.a, libfr.a, libfq.a
//!   RAPIDSNARK_GMP_LIB_DIR  dir holding libgmp.a (often a separate gmp package)
//!
//! prover.h is `extern "C"`, so the Rust side binds it directly (no cxx shim);
//! we only need the C++ stdlib on the link line since the libs are C++.

fn main() {
    if std::env::var_os("CARGO_FEATURE_RAPIDSNARK").is_none() {
        return;
    }

    let lib_dir = std::env::var("RAPIDSNARK_LIB_DIR").expect(
        "RAPIDSNARK_LIB_DIR must point at librapidsnark.a/libfr.a/libfq.a \
         when the `rapidsnark` feature is enabled",
    );
    println!("cargo:rustc-link-search=native={lib_dir}");

    // gmp is usually in its own package dir; fall back to lib_dir.
    let gmp_dir = std::env::var("RAPIDSNARK_GMP_LIB_DIR").unwrap_or_else(|_| lib_dir.clone());
    println!("cargo:rustc-link-search=native={gmp_dir}");

    // Static link order matters: rapidsnark depends on fr/fq, which depend on gmp.
    println!("cargo:rustc-link-lib=static=rapidsnark");
    println!("cargo:rustc-link-lib=static=fr");
    println!("cargo:rustc-link-lib=static=fq");
    println!("cargo:rustc-link-lib=static=gmp");

    // The rapidsnark libs are C++; pull in the platform C++ runtime.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
        // On Linux (the production image) rapidsnark is built with gcc OpenMP
        // for the multithreaded MSM — its static lib references omp_* symbols,
        // so link gcc's libgomp (the runtime needs libgomp1). gcc always
        // provides libgomp, so this resolves whether or not cmake actually
        // enabled OpenMP. (Skipped on macOS, where the local build is no-OpenMP.)
        println!("cargo:rustc-link-lib=dylib=gomp");
    }

    println!("cargo:rerun-if-env-changed=RAPIDSNARK_LIB_DIR");
    println!("cargo:rerun-if-env-changed=RAPIDSNARK_GMP_LIB_DIR");
}
