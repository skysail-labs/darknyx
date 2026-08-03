//! GPU confidential-compute detection (SW-32).
//!
//! Lives outside `icicle_prover` — which only compiles under the `icicle`
//! feature, and therefore only in a build nobody runs by default — because this
//! is the decision that lets the private match witness reach GPU memory. A
//! fail-closed security check whose tests never execute is not a check, and the
//! cases that matter most (empty output, an unrecognised string, a driver that
//! prints both words) are precisely the ones no GPU box produces on demand.
//!
//! The dead-code allow is scoped to exactly the configuration where the only
//! caller is absent, so a regression in an `icicle` build still fails.

/// What we could establish about the GPU's confidential-compute mode.
#[cfg_attr(not(feature = "icicle"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CcState {
    /// Confidential compute is enabled.
    On,
    /// The driver answered and reported it disabled.
    Off,
    /// We could not ask — no `nvidia-smi`, an error, or output we cannot parse.
    /// Treated exactly like `Off`; see `authorize_cuda`.
    Unknown,
}

/// Probe the driver for confidential-compute mode.
///
/// `nvidia-smi conf-compute -f` is the documented query and is present in any
/// image that can run CUDA at all. Parsing its text is not elegant, but the
/// alternative is an NVML binding for one boolean, and a wrong answer here
/// fails closed rather than silently permitting.
#[cfg_attr(not(feature = "icicle"), allow(dead_code))]
pub(crate) fn confidential_compute_state() -> CcState {
    let out = match std::process::Command::new("nvidia-smi")
        .args(["conf-compute", "-f"])
        .output()
    {
        Ok(out) if out.status.success() => out,
        _ => return CcState::Unknown,
    };
    parse_cc_output(&String::from_utf8_lossy(&out.stdout))
}

/// Interpret `nvidia-smi conf-compute -f` output.
///
/// Split out from the probe so the decision that gates the private witness is
/// testable without a GPU. Left inside `confidential_compute_state` it could
/// only ever be exercised on hardware, which for a fail-closed security check is
/// the same as untested — and the cases that matter most (empty output, an
/// unrecognised string) are exactly the ones no GPU box would produce.
pub(crate) fn parse_cc_output(stdout: &str) -> CcState {
    // WHOLE-VALUE matching, never `contains`. The first version of this used
    // `text.contains("ON") && !text.contains("OFF")`, which reads
    // "Confidential Compute: not supported on this device" as ENABLED — "ON"
    // is a substring of "CONFIDENTIAL" (and of "ON THIS"), and there is no
    // "OFF" anywhere in it. A driver reporting that CC is unavailable would
    // have authorized sending the private witness to an unprotected GPU. Its
    // own unit test caught it.
    //
    // So: only a status line whose value is EXACTLY an affirmative token
    // returns `On`. Everything else falls through to `Unknown`, which
    // `authorize_cuda` treats as a refusal.
    for line in stdout.lines() {
        let Some((_, value)) = line.split_once(':') else {
            continue;
        };
        match value.trim().to_ascii_uppercase().as_str() {
            "ON" | "ENABLED" => return CcState::On,
            "OFF" | "DISABLED" | "NOT SUPPORTED" => return CcState::Off,
            _ => continue,
        }
    }
    CcState::Unknown
}

#[cfg(test)]
mod cc_tests {
    use super::{parse_cc_output, CcState};

    /// SW-32 — the decision that lets the private witness reach GPU memory.
    ///
    /// The witness carries every per-slot amount, both owner commitments and
    /// the clearing price, so "CC is on" is the difference between encrypted
    /// device memory and memory the host driver can read. These four cases are
    /// the ones a GPU box cannot produce on demand, which is why they are here
    /// rather than in the parity gate.
    #[test]
    fn reports_on_only_for_an_unambiguous_enabled_answer() {
        assert_eq!(parse_cc_output("CC status: ON"), CcState::On);
        assert_eq!(parse_cc_output("cc status: on\n"), CcState::On);
    }

    #[test]
    fn reports_off_when_the_driver_says_disabled() {
        assert_eq!(parse_cc_output("CC status: OFF"), CcState::Off);
    }

    /// Both of these must FAIL CLOSED. `authorize_cuda` treats `Unknown`
    /// exactly like `Off`: not knowing whether the GPU protects this data and
    /// knowing that it does must never be the same outcome.
    #[test]
    fn empty_output_is_unknown_not_on() {
        assert_eq!(parse_cc_output(""), CcState::Unknown);
        assert_eq!(parse_cc_output("   \n"), CcState::Unknown);
    }

    #[test]
    fn unrecognised_output_is_unknown_not_on() {
        // A driver version that renames the field, a localised message, or an
        // error printed on stdout. Silence about CC is not consent.
        assert_eq!(
            parse_cc_output("Confidential Compute: not supported on this device"),
            CcState::Unknown
        );
        assert_eq!(parse_cc_output("Failed to query"), CcState::Unknown);
    }

    /// "ON" is a substring of ordinary English — "CONFIDENTIAL", "NOT
    /// SUPPORTED ON THIS DEVICE" — so a `contains` check reads several
    /// DISABLED answers as enabled. These are the strings that broke it.
    ///
    /// The assertion is "never On" rather than a specific state: both `Off`
    /// and `Unknown` are refusals, and which one an unparseable line lands on
    /// is not a property worth pinning. Authorizing is.
    #[test]
    fn a_substring_of_on_never_reads_as_enabled() {
        for s in [
            "Confidential Compute: not supported on this device",
            "CC status: not supported",
            "Confidential compute environment is not configured",
            "CC environment: ON, CC status: OFF",
        ] {
            assert_ne!(
                parse_cc_output(s),
                CcState::On,
                "must not authorize CUDA on: {s:?}"
            );
        }
    }
}
