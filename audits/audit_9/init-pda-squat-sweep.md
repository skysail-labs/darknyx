# audit_9 — proof-not-bound-to-signer / `init` PDA squatting

**Date:** 2026-08-18
**Trigger:** CodeRabbit raised the `create_wallet` case on PR #170 (the Anchor v2
port). This document is the finding plus the **program-wide sweep for the same
pattern** that the report was asked to produce.
**Scope:** every `#[derive(Accounts)]` in `programs/vault/src/instructions/`.

> **This is not a v2 regression.** `create_wallet` on `main` under Anchor 1.1.2
> has the identical single public input and the identical unconstrained signer.
> The port surfaced it; it did not cause it. Fixing it is therefore independent
> of the port and must not be folded into that stack.

---

## 1. The pattern

Two properties combine into a griefing DoS:

1. **A verifying handler whose proof does not bind the signer.** The
   `(args, proof)` pair is public in a landed transaction, so anyone can replay
   it with themselves in the signer slot.
2. **An `init` PDA whose seeds are entirely derivable from those same public
   args.** `init` is one-shot, so whoever lands first owns the address forever.

Either alone is harmless. Together, an attacker who replays the observed
transaction first permanently occupies the address the legitimate user needs,
and the user has no second address to move to when the seed is derived from
their own long-lived identity.

**The mitigating property, where it exists, is that the proof binds the
*effect*** — so a replay reproduces the same state transition at the replayer's
expense and gains them nothing.

---

## 2. Sweep results — all five proof-verifying handlers

| Handler | Public inputs | Signer bound? | `init` PDA seeded by | Verdict |
|---|---|---|---|---|
| `create_wallet` | `[commitment]` | **no** | `commitment` | **VULNERABLE — F-11** |
| `deposit` | `[commitment, mint_lo, mint_hi, amount, recovery_nonce]` | no | `note_commitment` | **Bounded — F-12** |
| `verify_match_batch` | `[merkle_root, config_digest]` | no (any payer, by design) | `merkle_root` | **Interaction — F-13** |
| `lock_note` | `[merkle_root, note_use_tag, mint_lo, mint_hi]` | **yes** — `tee_pubkeys` | `note_use_tag` | Safe |
| `withdraw` | `[tag, root, nullifier, mint_lo/hi, amount, dest_lo, dest_hi]` | no | `note_use_tag` | Safe — **binds destination** |
| `merge` | `[out_commitment, in_tags…, root, mint_lo/hi]` | no | `note_use_tag` ×K | Safe — binds the effect |

`withdraw` is the model. It has an unconstrained signer too, but `dest_lo`/
`dest_hi` are public inputs, so a replay pays the fee to send the same tokens to
the same account the original proof authorised. The proof binds *where the value
goes*, which is what makes the signer irrelevant.

`merge` is safe for the same structural reason: the output commitment and every
input tag are public, so a replayer can only perform the user's own merge, for
the user, at their own cost.

---

## 3. F-11 — `create_wallet` wallet-identity squatting

**Severity: Medium.** Griefing, permanent, rent-cheap. Not theft.

`programs/vault/src/instructions/create_wallet.rs`

```rust
let public_inputs: [[u8; 32]; 1] = [commitment];   // the ONLY public input
…
w.owner = *ctx.accounts.owner.address();           // whoever signed
```

with

```rust
seeds = [WalletEntry::SEED, commitment.as_ref()], init
```

**Attack.** Observe a `create_wallet` transaction. Resubmit `(commitment, proof)`
verbatim with your own key in the `owner` slot and win the race. You now hold
`PDA(["wallet", commitment])` with `wallet_entry.owner = attacker`. The
legitimate user's transaction fails, and every retry fails identically —
**there is no `close_wallet` instruction**, so the address is unrecoverable.

**Why the user cannot route around it.** The commitment is
`userCommitmentFromKeys(root_key, spending_key, viewing_key, r0, r1, r2)` — a
deterministic function of their long-lived identity. Picking a fresh commitment
means rotating the wallet, not retrying.

**Cost to attacker:** one transaction fee plus ~0.001 SOL rent, unrecoverable.
Cheap enough to do to every registration on the venue.

**What bounds the impact today.** `WalletEntry` is **written and never read** —
no on-chain instruction consults it, and `wallet_entry.owner` authorises nothing.
So this is denial of registration and corruption of the public
`WalletCreated` attribution, **not** impersonation or fund access. That bound is
incidental, not designed: the moment anything starts trusting
`wallet_entry.owner`, this becomes an identity-confusion bug.

**Fix options, cheapest first.**

- **(A) Add `owner` to the PDA seeds** — `seeds = [SEED, commitment, owner]`.
  The squatter takes a different address and cannot block anyone. Two entries
  may exist per commitment, which is fine precisely because nothing reads them
  for authorisation, and it makes the entry mean what it actually is: *this
  signer registered this commitment*. Touches the seed derivation, so
  `sdk/src/idl/seeds.ts` + `walletEntryPda()` + tests move with it (CLAUDE.md
  §8.3). No circuit change.
- **(B) Bind the owner into the proof** — add the owner pubkey as two Fr halves
  to VALID_WALLET_CREATE's public inputs. Cryptographically correct, and it makes
  the on-chain `owner` field trustworthy for future consumers. Cost is the full
  CLAUDE.md §5 circuit lockstep: `.zkey` + `vk_valid_wallet_create.rs` + SDK
  prover inputs + fixtures in one commit, plus a redeploy.
- **(C) Accept and record**, on the ground that `WalletEntry` has no reader.
  Only defensible while that stays true, and nothing enforces that it stays true.

**Recommendation: (A) now, (B) before anything reads `wallet_entry.owner`.**

---

## 4. F-12 — `deposit` commitment squatting (bounded by cost)

**Severity: Low.**

`deposited_note` is `init` on `[DepositedNoteEntry::SEED, note_commitment]` with
an unconstrained `depositor`. A replayer can squat a victim's note commitment —
but the same instruction transfers `amount` of the mint out of *their* token
account, and they cannot produce the VALID_SPEND proof to get it back, because
they do not know the note's `inner_hash`.

So the grief costs the attacker the full note amount, permanently. Real, but
economically self-limiting; recorded rather than fixed. It escalates if a
zero-amount or dust deposit is ever accepted for a commitment — check that
before relaxing any amount constraint.

---

## 5. F-13 — `verify_match_batch` marker payer capture

**Severity: Low, but it interacts with a change made in this port.**

`payer` is deliberately "anyone" (the handler's own comment says so, correctly:
authorisation is the proof). The marker is `init` on `[SEED, merkle_root]`.

An observer can front-run the TEE's Tx B with the same proof and become
`marker.payer`. The marker content is still correct and the batch still settles,
so this is not a settlement-integrity issue. Two consequences:

1. The TEE's own Tx B fails with an already-initialised account. Whether that is
   handled or fatal is a **settle-pipeline** question, not a program one.
2. **After this port's §3.1 change, only `marker.payer` can close the marker.**
   A captured marker is therefore never swept: its rent is stranded and
   `marker_sweep.rs` retries it forever. Under Anchor v1's three-account shape
   any signer could have swept it.

This is the honest cost of collapsing the close-marker slots to dodge
`ConstraintDuplicateMutableAccount`. It was the right call for the aliasing
problem; it narrows recovery here. Worth revisiting together with F-11, since
both are "the signer is unconstrained and the PDA is one-shot".

---

## 6. What was checked and found clean

- `lock_note` — signer gated to `vault_config.tee_pubkeys`; not publicly
  squattable.
- `withdraw`, `merge` — proof binds the effect (destination / output+inputs), so
  replay is a no-op for the attacker.
- `initialize`, `initialize_tree`, `initialize_market` — admin/upgrade-authority
  gated. (`initialize`'s own front-run window is audit_1 **F-03**, already
  tracked; not re-litigated here.)
- `tee_forced_settle_batched`'s `ConsumedNoteEntry` inits — `tee_authority`
  gated, and the tags come from a marker-bound payload.
- `deposit`'s `init_if_needed` accounts (`vault_token_account`,
  `outstanding_mint`) — keyed by mint, shared infrastructure, no per-user
  address to deny.
