# `crates/darkpool-crypto` — documentation remediation plan

> **Status:** plan. Written 2026-08-22.
> **Scope:** `crates/darkpool-crypto` (25 files, 2,129 lines src + 359 examples).
> `darkpool-matcher` follows separately.
> **Conventions:** `CLAUDE.md` §10.5 — already written, nothing new to author.

---

## 1. This crate is not in the state `darknyx-tee` was in

Surveyed 2026-08-22. Stating the difference up front, because the tee plan's
shape does not transfer and repeating it would manufacture work:

| | `darknyx-tee` | `darkpool-crypto` |
|---|---:|---:|
| files | 108 | 25 |
| process markers (`4g.3`, `Phase 2`) | ~130 | **0** |
| transitional narration | ~22 | 2 |
| files with no `//!` header | 0 | 1 |
| audit IDs | ~155 | 1 |

**The marker sweep — the bulk of the tee work — is a no-op here.** Headers are
mostly present, present-tense, and formula-accurate. `deposit.rs` (40 lines),
`note_use.rs` (57), `fill_encryption.rs` (35), and `keys.rs` (31) are already at
or above the standard §10.5 asks for.

So this is a **short, targeted pass**, not a rewrite.

## 2. What is actually wrong

### 2.1 Two dead cross-references

Both point at things that do not exist, which is the readability trap §10.5's
"where is the authority" question exists to prevent:

- **`price_commitment.rs`** cites `circuits/valid_price/circuit.circom`. That
  circuit is **gone**. `circuits/` holds nine circuits and `valid_price` is not
  among them; `programs/vault/.../settlement_shared.rs:124` records that the
  path "was since subsumed by the batched VALID_MATCH_BATCH proof", and
  `circuits/templates/match_batch.circom:286` refers to "the old VALID_PRICE".
- **`viewing_keys.rs`** cites `darkpool_protocol_spec_v3_changed.md` §23.2.2 and
  Appendix C. **No such file exists anywhere in the repository.** It may be an
  external document; from a reader's position inside the repo it is
  unresolvable.

### 2.2 `price_commitment` is vestigial, in two languages

Beyond the dead reference, the module itself has no live consumer. It is
exported from `lib.rs`, mirrored by `packages/sdk/src/zk/price-commitment.ts`,
and used by nothing. Deleting it is a code change and therefore **out of scope
here** — it is recorded in §5 for a separate decision.

### 2.3 Future tense about shipped code

`poseidon.rs`: "The on-chain verifier (vault program) **will call**
`solana_poseidon::hashv` directly." It already does. §10.5 forbids exactly this.

### 2.4 `errors.rs` has no header

The only such file in the crate.

### 2.5 Thin headers on consensus-critical modules

Length is not the metric — several short headers here are good. But these carry
a byte-equality contract and do not say so:

| file | header | code | contract it is silent about |
|---|---:|---:|---|
| `match_config.rs` | 6 | 99 | digest recomputed on-chain by `verify_match_batch` |
| `match_output.rs` | 5 | 72 | mirrored by `e2e-helpers.ts::deriveInner` |
| `merge.rs` | 5 | 89 | `merge-inner-parity.test.ts` |
| `viewing_keys.rs` | 14 | 174 | — |

### 2.6 The crate's defining property is under-stated

`lib.rs` says output must be byte-identical across four environments and that a
mismatch can permanently lock funds — which is right, and is the most important
sentence in the crate. What it does not do is say **how that is enforced**:
every primitive here is pinned by a named parity test in `packages/sdk/tests/`
(CLAUDE.md §7.1), and the examples under `examples/` exist solely so those tests
can shell out to them. A reader who does not know that will change a hash and
watch a TypeScript test fail for reasons that look unrelated.

`REQUIRE_PARITY_HELPERS=1` turning a missing example into a hard failure is part
of the same contract and is worth one line.

---

## 3. Phases

Three, not five. Each is independently reviewable.

### Phase 1 — Factual corrections

The §2.1–2.4 items: two dead references, one future tense, one missing header.
Small and unambiguous.

### Phase 2 — The byte-equality contract

Rewrite `lib.rs` to state how the guarantee is enforced (§2.6), and give the
four §2.5 modules the contract line they lack — which parity test pins them, and
what a divergence looks like. Naming the failure is the §10.5 rule that pays
most here, because a Poseidon drift does not fail locally: it fails as a
TypeScript parity assertion, or on devnet as `InvalidProof (6000)`.

### Phase 3 — Guard extension and verification

Extend `scripts/check-no-process-markers.sh` to `darkpool-crypto` (0 markers
today, so it starts and stays green), verify every remaining cross-reference
resolves, and confirm `cargo doc` adds no warnings.

The guard currently takes one path argument. Extending it to several crates is a
loop; `darkpool-matcher` joins when its own pass lands.

---

## 4. Validation

Per phase:

```sh
cargo fmt --all -- --check
cargo clippy -p darkpool-crypto --all-targets -- -D warnings
cargo nextest run -p darkpool-crypto
cargo build --examples -p darkpool-crypto      # the parity helpers must still build
cargo doc --no-deps -p darkpool-crypto
bash scripts/check-no-process-markers.sh crates/darkpool-crypto
```

Plus, because this crate's contract is cross-language, the parity suite itself:

```sh
( cd packages/sdk && REQUIRE_PARITY_HELPERS=1 ../../node_modules/.bin/vitest run )
```

A docs-only change cannot break it — running it is how that claim is checked
rather than assumed.

---

## 5. Raised, not fixed

**`price_commitment` is dead code in Rust and TypeScript** (§2.2). Removing it
touches `lib.rs` exports, `packages/sdk/src/zk/price-commitment.ts`, and any
test importing either. That is a code change, not a documentation one, and is
left as an explicit decision. Until it is taken, Phase 1 makes the module's
header honest about the circuit being retired rather than pointing at a path
that does not exist.
