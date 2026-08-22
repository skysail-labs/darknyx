# Contributing to `darknyx-tee`

This crate is the in-enclave matching and settlement engine. Most of it is
pinned by contracts it does not own — on-chain account layouts, circuit public
inputs, wire formats mirrored in the TypeScript SDK. A header comment here is
usually the only place those constraints are written down next to the code that
depends on them.

## Documentation conventions

### A module header answers four questions, in this order

1. **What is this?** One sentence, present tense, no history.
2. **Where does it sit?** What calls it, what it calls, its place in the
   pipeline.
3. **What must not break?** Wire layouts, ordering constraints, arity caps,
   invariants — and what fails if they are violated.
4. **Where is the authority?** The canonical doc, or the counterpart
   implementation this file must stay byte-identical to.

### Rules

- **Present tense, describing what the code does now.** Never "will be", "for
  now", "was added in", "used to". A reader cannot verify a claim about the
  past and should not have to.
- **No implementation-process references.** No PR numbers, phase names, slice
  or step numbers. `scripts/check-no-process-markers.sh` enforces this.
- **State invariants as invariants, not as history.** "The account list must
  match the on-chain struct order" — not "PR 4g.3 reordered the accounts".
- **Keep load-bearing numbers.** Byte widths, account indices, discriminators,
  and arities are the contract. They stay, and they stay exact.
- **Do not restate the code.** `LazyLock` needs no explanation. Explain what
  the code cannot say: why an order is mandatory, what breaks if it changes,
  where the mirrored implementation lives.
- **Name the failure.** Where a subtle invariant exists, say how a violation
  surfaces — `InvalidProof (6000)`, `ConstraintSeeds (2006)`, `AccountNotFound`,
  `StaleMerkleRoot (6004)`. This is what turns a comment into a debugging aid.

### Audit references

Findings under `audits/` are indexed by `audits/residual-backlog.md`, and some
are still open. An audit ID may be cited, but **only alongside the substance,
never as the sole explanation**:

```rust
// Wrong — explains nothing:
//   consumed_note is read-only (U-02)

// Right — the invariant first, the reference as a pointer:
//   `consumed_note` is read-only and must be ABSENT: its existence is the
//   consume-once guard that stops a note being locked twice (audit U-02).
```

If you cannot state the invariant in plain language, the ID is not a substitute
for understanding it.

## Before you push

Run the crate's slice of the repo gate (`CLAUDE.md` §2.5):

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run -p darknyx-tee
REQUIRE_CIRCUIT_ARTIFACTS=1 cargo nextest run -p darknyx-tee --tests
cargo doc --no-deps -p darknyx-tee
bash scripts/check-no-process-markers.sh
```

`cargo doc` matters for documentation changes specifically: doc comments on
public items participate in intra-doc link resolution, so a malformed link is a
build warning, not a silent typo.
