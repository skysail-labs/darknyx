use cmake::Config;
use std::{env, path::PathBuf};

fn main() {
    // Construct the path to the deps directory
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is not set");
    let build_dir = PathBuf::from(format!("{}/../../../", &out_dir));
    let deps_dir = build_dir.join("deps");

    let main_dir = env::current_dir().expect("Failed to get current directory");
    let icicle_src_dir = PathBuf::from(format!("{}/../../../icicle", main_dir.display()));

    println!("cargo:rerun-if-env-changed=CXXFLAGS");
    println!("cargo:rerun-if-changed={}", icicle_src_dir.display());

    // Base config
    let mut config = Config::new(format!("{}", icicle_src_dir.display()));
    // Check if ICICLE_INSTALL_DIR is defined
    let icicle_install_dir = if let Ok(dir) = env::var("ICICLE_INSTALL_DIR") {
        PathBuf::from(dir)
    } else {
        // Define the default install directory to be under the build directory
        PathBuf::from(format!("{}/icicle/", deps_dir.display()))
    };
    config.define("CMAKE_INSTALL_PREFIX", &icicle_install_dir);

    // build (or pull and build) cuda backend if feature enabled.
    // Note: this requires access to the repo
    if cfg!(feature = "cuda_backend") {
        config.define("CUDA_BACKEND", "local");
    } else if cfg!(feature = "pull_cuda_backend") {
        config.define("CUDA_BACKEND", "main");
    }
    // Forward an explicit CUDA arch so the cmake CUDA build does NOT fall back to
    // `CMAKE_CUDA_ARCHITECTURES native` (Common.cmake set_gpu_env), which probes the
    // live GPU and FAILS on a GPU-less build host (our CI image builder). The cmake
    // honours `-DCUDA_ARCH` as the user override. NYX_ICICLE_CUDA_ARCH=90 => H200 /
    // Hopper (sm_90). Unset => unchanged, so a local build with a GPU still
    // auto-detects. (nyx-monorepo addition over upstream icicle.)
    println!("cargo:rerun-if-env-changed=NYX_ICICLE_CUDA_ARCH");
    if cfg!(any(feature = "cuda_backend", feature = "pull_cuda_backend")) {
        if let Ok(arch) = env::var("NYX_ICICLE_CUDA_ARCH") {
            if !arch.is_empty() {
                config.define("CUDA_ARCH", arch);
            }
        }
    }
    if cfg!(feature = "metal_backend") {
        config.define("METAL_BACKEND", "local");
    } else if cfg!(feature = "pull_metal_backend") {
        config.define("METAL_BACKEND", "main");
    }
    if cfg!(feature = "vulkan_backend") {
        config.define("VULKAN_BACKEND", "local");
    } else if cfg!(feature = "pull_vulkan_backend") {
        config.define("VULKAN_BACKEND", "main");
    }

    // Build
    let _ = config.build_target("install").build();

    println!(
        "cargo:rustc-link-search={}/lib",
        icicle_install_dir.display()
    );
    println!("cargo:rustc-link-lib=icicle_device");
    println!(
        "cargo:rustc-link-arg=-Wl,-rpath,{}/lib",
        icicle_install_dir.display()
    ); // Add RPATH linker arguments

    // default backends dir
    if cfg!(feature = "cuda_backend")
        || cfg!(feature = "pull_cuda_backend")
        || cfg!(feature = "metal_backend")
        || cfg!(feature = "pull_metal_backend")
    {
        println!(
            "cargo:rustc-env=ICICLE_BACKEND_INSTALL_DIR={}/lib/backend",
            icicle_install_dir.display()
        );
    }
}
