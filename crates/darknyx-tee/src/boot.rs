//! Boot-time dstack handshake.
//!
//! Stages (per `docs/tee-architecture.md` §3):
//!   1. Connect to the dstack socket (`DSTACK_SIMULATOR_ENDPOINT` in
//!      local dev; `/var/run/dstack.sock` in a real CVM — the
//!      `DstackClient::new(None)` picks the right one).
//!   2. `info()` → app_id, instance_id, compose_hash, MRTD.
//!   3. Derive the Ed25519 signer via
//!      `dstack.get_key("darknyx/ed25519-signer/v2")` →
//!      `SigningKey::from_bytes(seed)`.
//!   4. Log the resulting Solana base58 pubkey so an operator can
//!      cross-check against the on-chain `vault_config.tee_pubkey`
//!      before running the rotation ceremony.
//!
//! Returns the derived signer to `main.rs`, which threads it
//! through to the settle-pipeline + the API server's `/info`
//! endpoint.
//!
//! A failed handshake is returned to `main`, which fails production startup.
//! Only an explicitly configured local simulator test mode may substitute test
//! state after this function returns an error.

use std::time::{Duration, Instant};

use anyhow::Result;

use crate::keys::ed25519::{self, DerivedSigner};

/// Boot-time host-CPU profile — the answer to PERF-INV-01 without SSH.
///
/// The 10× proving/witness/auth latency regression observed on Phala CVMs is
/// invisible from the code (argon2 auth, single-threaded witness gen, and the
/// prover all slowed together, which only a per-core throughput collapse
/// explains). Phala's `phala ssh` gateway rejects the key, so `cpu.max` /
/// `cpu.stat` / `cpuinfo` could never be read from outside. But this binary
/// runs *inside* the CVM — so it just reads them itself and logs one line.
///
/// Reads (best-effort; all `None` off-Linux, e.g. local macOS dev):
///   - `available_parallelism()` — cores the scheduler will actually hand us
///     (respects the cgroup cpuset).
///   - `/proc/cpuinfo` — host CPU model, current MHz, visible processor count.
///   - cgroup v2 `/sys/fs/cgroup/cpu.max` — the CPU *bandwidth* quota. If this
///     is e.g. `50000 100000` (0.5 CPU) while 8 cores are "visible", the box is
///     hard-throttled — that is the regression.
///   - cgroup v2 `/sys/fs/cgroup/cpu.stat` — `nr_throttled` / `throttled_usec`.
///     Nonzero and climbing across boots ⇒ the kernel is actively parking us.
///   - a time-boxed single-thread micro-benchmark (~100 ms budget, so it never
///     delays boot on a slow host) whose throughput (Mops/s) is directly
///     comparable across hosts and across images. A fast host scores several
///     hundred Mops/s; a throttled one a fraction of that. This is the single
///     number to diff against the historical baseline.
///
/// Emits at INFO so it lands in the normal boot log an operator already reads.
pub fn log_host_cpu_profile() {
    let logical = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    // /proc/cpuinfo: first `model name`, first `cpu MHz`, count of `processor`.
    let (cpu_model, cpu_mhz, cpuinfo_procs) = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(s) => {
            let model = s
                .lines()
                .find_map(|l| l.strip_prefix("model name").map(field_value))
                .unwrap_or_else(|| "unknown".to_string());
            let mhz = s
                .lines()
                .find_map(|l| l.strip_prefix("cpu MHz").map(field_value))
                .unwrap_or_else(|| "n/a".to_string());
            let procs = s.lines().filter(|l| l.starts_with("processor")).count();
            (model, mhz, procs)
        }
        Err(_) => ("n/a (non-Linux)".to_string(), "n/a".to_string(), 0),
    };

    // cgroup v2 first, then v1 fallback.
    let cpu_max = read_trim("/sys/fs/cgroup/cpu.max")
        .or_else(cgroup_v1_cpu_max)
        .unwrap_or_else(|| "n/a".to_string());
    let effective_cpus = parse_effective_cpus(&cpu_max);

    let cpu_stat =
        read_trim("/sys/fs/cgroup/cpu.stat").or_else(|| read_trim("/sys/fs/cgroup/cpu/cpu.stat"));
    let (nr_periods, nr_throttled, throttled_usec) = match &cpu_stat {
        Some(s) => (
            stat_field(s, "nr_periods"),
            stat_field(s, "nr_throttled"),
            // cgroup v2 reports microseconds; v1 reports `throttled_time` in ns.
            stat_field(s, "throttled_usec").or_else(|| stat_field(s, "throttled_time")),
        ),
        None => (None, None, None),
    };

    // Time-boxed single-thread throughput probe. Fixed inner work, ~100 ms
    // budget → bounded boot cost, host-comparable score.
    let (ops, bench_ms) = cpu_microbench(Duration::from_millis(100));
    let mops_per_s = if bench_ms > 0 {
        (ops as f64) / (bench_ms as f64) / 1000.0
    } else {
        0.0
    };

    tracing::info!(
        logical_cpus = logical,
        cpuinfo_procs = cpuinfo_procs,
        cpu_model = %cpu_model,
        cpu_mhz = %cpu_mhz,
        cgroup_cpu_max = %cpu_max,
        effective_cpus = effective_cpus
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "unlimited/n/a".to_string()),
        nr_periods = nr_periods.map(|v| v.to_string()).unwrap_or_default(),
        nr_throttled = nr_throttled.map(|v| v.to_string()).unwrap_or_default(),
        throttled_usec = throttled_usec.map(|v| v.to_string()).unwrap_or_default(),
        singlethread_mops_per_s = format!("{mops_per_s:.1}"),
        microbench_ops = ops,
        microbench_ms = bench_ms,
        "host-cpu profile (PERF-INV-01: compare singlethread_mops_per_s + effective_cpus + nr_throttled against the fast baseline)"
    );
}

/// `key : value` (or `key\tvalue`) → the trimmed value half.
fn field_value(rest: &str) -> String {
    rest.trim_start().trim_start_matches(':').trim().to_string()
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Synthesize a cgroup-v2-style `"<quota> <period>"` from cgroup v1 files.
fn cgroup_v1_cpu_max() -> Option<String> {
    let quota = read_trim("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")?;
    let period = read_trim("/sys/fs/cgroup/cpu/cpu.cfs_period_us")?;
    let quota = if quota.trim() == "-1" {
        "max".to_string()
    } else {
        quota
    };
    Some(format!("{quota} {period}"))
}

/// `cpu.max` is `"<quota> <period>"` (or `"max <period>"`). Returns the
/// effective CPU count (quota/period), or `None` when unlimited/unparseable.
fn parse_effective_cpus(cpu_max: &str) -> Option<f64> {
    let mut it = cpu_max.split_whitespace();
    let quota = it.next()?;
    let period: f64 = it.next()?.parse().ok()?;
    if quota == "max" || period <= 0.0 {
        return None;
    }
    let quota: f64 = quota.parse().ok()?;
    Some(quota / period)
}

/// Extract a `"<key> <u64>"` value from a cgroup stat blob.
fn stat_field(blob: &str, key: &str) -> Option<u64> {
    blob.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == key)
            .then(|| it.next())
            .flatten()?
            .parse()
            .ok()
    })
}

/// Single-thread integer throughput, time-boxed to `budget`. Returns
/// `(ops_performed, elapsed_ms)`. The inner op is a splitmix64 step; the
/// accumulator is `black_box`ed so the loop can't be optimized away.
fn cpu_microbench(budget: Duration) -> (u64, u64) {
    let start = Instant::now();
    let mut acc: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut ops: u64 = 0;
    const CHUNK: u64 = 1 << 16;
    loop {
        for _ in 0..CHUNK {
            acc = acc
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            acc ^= acc >> 29;
        }
        ops += CHUNK;
        if start.elapsed() >= budget {
            break;
        }
    }
    std::hint::black_box(acc);
    (ops, start.elapsed().as_millis() as u64)
}

/// Connect to dstack + derive the signer. Logs all the
/// human-readable fields (app_id, compose_hash, signer pubkey).
/// Returns the derived signer on success.
pub async fn probe_dstack() -> Result<DerivedSigner> {
    // DstackClient::new(None) picks up DSTACK_SIMULATOR_ENDPOINT
    // from the env if set; otherwise falls back to
    // /var/run/dstack.sock.
    let client = dstack_sdk::dstack_client::DstackClient::new(None);

    let info = match client.info().await {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(
                error = %e,
                "dstack.info() failed; production startup must terminate. \
                 Local development requires a running simulator and explicit \
                 DARKNYX_TEE_ALLOW_TEST_AUTH=1 for test-state fallback."
            );
            anyhow::bail!("dstack unreachable: {}", e);
        }
    };

    tracing::info!(
        app_id = %info.app_id,
        instance_id = %info.instance_id,
        app_name = %info.app_name,
        device_id = %info.device_id,
        compose_hash = %info.compose_hash,
        mrtd = %info.tcb_info.mrtd,
        "dstack handshake — info() succeeded"
    );

    // Shard 0's signer. The full K-signer set (one fee-payer per shard) is
    // derived in `main.rs` via `ed25519::derive_set` once `num_trees` is known;
    // this primary is what `/info` advertises + the operator cross-checks.
    let signer = ed25519::derive(&client, 0).await?;

    // Logging the signer pubkey on boot is intentional — it's what
    // an operator pastes into the multisig rotation proposal at
    // image-upgrade time. The PRIVATE half (signer.key) is never
    // logged.
    tracing::info!(
        path = %ed25519::signer_path(0),
        pubkey_base58 = %signer.pubkey_base58,
        pubkey_hex = %signer.pubkey_hex,
        "dstack handshake — derived shard-0 Ed25519 signer (register the full set in vault_config.tee_pubkeys)"
    );

    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The microbench is deterministic-effort and never zero.
    #[test]
    fn microbench_makes_progress() {
        let (ops, ms) = cpu_microbench(Duration::from_millis(20));
        assert!(ops > 0, "microbench performed no work");
        assert!(ms > 0, "microbench reported zero elapsed");
    }

    #[test]
    fn parses_cgroup_v2_cpu_max() {
        assert_eq!(parse_effective_cpus("max 100000"), None);
        assert_eq!(parse_effective_cpus("50000 100000"), Some(0.5));
        assert_eq!(parse_effective_cpus("800000 100000"), Some(8.0));
        assert_eq!(parse_effective_cpus("garbage"), None);
    }

    #[test]
    fn extracts_stat_fields() {
        let blob = "nr_periods 42\nnr_throttled 7\nthrottled_usec 123456\n";
        assert_eq!(stat_field(blob, "nr_periods"), Some(42));
        assert_eq!(stat_field(blob, "nr_throttled"), Some(7));
        assert_eq!(stat_field(blob, "throttled_usec"), Some(123456));
        assert_eq!(stat_field(blob, "absent"), None);
    }

    /// Manual: prints THIS host's profile — the local reference number to
    /// diff against a CVM boot log. `cargo test -p darknyx-tee --release \
    /// host_cpu_profile_smoke -- --ignored --nocapture`.
    #[test]
    #[ignore = "manual host-profile probe; run with --ignored --nocapture"]
    fn host_cpu_profile_smoke() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        log_host_cpu_profile();
    }
}
