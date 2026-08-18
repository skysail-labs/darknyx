# audit_10 — proof-not-bound-to-signer / `init` PDA squatting

**Date:** 2026-08-18
**Trigger:** CodeRabbit raised the `create_wallet` case on PR #170 (the Anchor v2
port). This document is the **program-wide sweep for that pattern**.

> **`create_wallet` itself is already tracked as `audit_9` TR-14**, filed
> independently and merged to `main` (#176) while this port was in flight.
> **This document does not re-file it.** §3 is an AMENDMENT to TR-14's
> disposition, not a new finding. PS-01 and PS-02 ARE new — `audit_9` covers
> neither.
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

## 2. Sweep results — all six proof-verifying handlers

| Handler | Public inputs | Signer bound? | `init` PDA seeded by | Verdict |
|---|---|---|---|---|
| `create_wallet` | `[commitment]` | **no** | `commitment` | **VULNERABLE — `audit_9` TR-14; see §3** |
| `deposit` | `[commitment, mint_lo, mint_hi, amount, recovery_nonce]` | no | `note_commitment` | **Bounded — PS-01** |
| `verify_match_batch` | `[merkle_root, config_digest]` | no (any payer, by design) | `merkle_root` | **Interaction — PS-02** |
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

## 3. Amendment to `audit_9` TR-14 — `create_wallet`

**Not a new finding.** TR-14 already records the front-run, the single public
input, and the grep proving nothing reads `WalletEntry.owner`. Two corrections
to its disposition — one makes it worse, one makes it cheaper to fix.

**(i) TR-14's Low is understated.** It reads the impact as "rent-burn and a
misattributed registry row, nothing more". The registration is not merely
misattributed — it becomes **impossible**. `wallet_entry` is `init` and there is
no `close_wallet`, so the address is occupied permanently; and the commitment is
`userCommitmentFromKeys(root_key, spending_key, viewing_key, r0, r1, r2)`, a
deterministic function of the user's long-lived identity, so the victim cannot
simply choose another. The impact is **permanent denial of registration to a
specific user**, for one fee plus ~0.001 SOL of unrecoverable rent. Suggested
severity: **Medium**.

**(ii) TR-14 marks this `Lockstep: yes` and offers only a circuit change.**
Option (A) below fixes it without touching the circuit. This matters because
"the fix is a lockstep circuit change" is precisely what leaves a Low finding
sitting unfixed.

The original analysis follows.

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
  `packages/sdk/src/idl/seeds.ts`, `walletEntryPda()` in `vault-client.ts`, and
  the tests that derive the address all move with it in the SAME commit
  (CLAUDE.md §8.3 — CI does NOT catch a missed SDK mirror; only the integration
  tests do, as `AccountNotFound` / `ConstraintSeeds (2006)`). No circuit change.
- **(B) Bind the owner into the proof** — add the owner pubkey as two Fr halves
  to VALID_WALLET_CREATE's public inputs. Cryptographically correct, and it makes
  the on-chain `owner` field trustworthy for future consumers. Cost is the full
  CLAUDE.md §5 circuit lockstep: `.zkey` + `vk_valid_wallet_create.rs` + SDK
  prover inputs + fixtures in one commit, plus a redeploy.
- **(C) Accept and record**, on the ground that `WalletEntry` has no reader.
  Only defensible while that stays true, and nothing enforces that it stays true.

**Recommendation: (A) now, (B) before anything reads `wallet_entry.owner`.**

> **Resolved 2026-08-19 — (A) shipped.** `wallet_entry` is now
> `PDA([b"wallet", commitment, owner])`. No circuit change. Mirrored in the SDK
> (`walletEntryPda` now requires the owner) and both litesvm helpers.
> Mutation-tested twice. **(B) is still open and still required before any
> reader of `wallet_entry.owner` exists** — seeds prove who paid rent, not who
> holds the commitment's keys.

---

## 4. PS-01 — `deposit` commitment squatting (bounded by cost)

**Severity: Low.**

`deposited_note` is `init` on `[DepositedNoteEntry::SEED, note_commitment]` with
an unconstrained `depositor`. A replayer can squat a victim's note commitment —
but the same instruction transfers `amount` of the mint out of *their* token
account, and they cannot produce the VALID_SPEND proof to get it back, because
they do not know the note's `inner_hash`.

So the grief costs the attacker the full note amount, permanently. It escalates
if a zero-amount or dust deposit is ever accepted for a commitment — check that
before relaxing any amount constraint.

> **Won't Fix, 2026-08-19 — and the reason matters more than the verdict.**
> The symmetric remedy, adding `depositor` to `DepositedNoteEntry`'s seeds,
> would **reintroduce the bug the guard exists to prevent**. `state.rs` spells
> it out: two deposits sharing a commitment both move tokens in and both
> increment `outstanding`, but only ONE can ever be withdrawn — the vault ends
> up permanently over-collateralised, so no solvency alarm fires, and the second
> deposit is silently unrecoverable. It is reachable by ACCIDENT, not only by
> malice, because `recovery_nonce = deriveBlindingFactor(seed, depositIndex)` is
> deterministic and the SDK persists `depositIndex` nowhere.
>
> **The global keying is the feature.** This is the case where the pattern in §1
> holds structurally but the fix that works for `create_wallet` is the wrong
> move here — worth stating explicitly, because "apply the same fix to every row
> in the sweep" is the obvious next step and it would be a regression.

---

## 5. PS-02 — `verify_match_batch` marker capture stalls the batch

**Severity: Medium.** Raised from Low after review — see the correction note at
the end of this section.

**A cheap, repeatable liveness attack on settlement.**

`payer` is deliberately "anyone" (the handler's own comment says so, correctly:
authorisation is the proof). The marker is `init` on `[SEED, merkle_root]`.

An observer can front-run the TEE's Tx B with the same proof and become
`marker.payer`. Three consequences, in increasing order of severity:

1. **The batch fails outright.** `settle/worker.rs` does
   `submit_ixs(&ctx.rpc, ctx.primary_keypair(), &verify_ixs).await?` — the `?`
   propagates the already-initialised-account error, and **nothing anywhere in
   `crates/darknyx-tee/src/settle/` reconciles an existing marker** (grepped for
   `already_initiali` / `AlreadyInUse` / `marker_exists`: no hits). The batch
   never reaches Tx D.
2. **Both sides' notes stay locked until lock expiry.** The `lock_note` Tx As
   already landed before the prove/verify branch, so a failed Tx B leaves them
   pinned with no settlement and no early release; only the lock sweeper
   reclaims them, at expiry.
3. **After this port's §3.1 change, only `marker.payer` can close the marker.**
   The captured marker is therefore never swept: its rent is stranded and
   `marker_sweep.rs`, which signs with the primary TEE key, retries and fails
   forever. Under Anchor v1's three-account shape any signer could have swept it.

Settlement *integrity* is untouched — the marker content is correct and no
value moves incorrectly. What is attacked is liveness, and it is cheap: one
transaction per batch, repeatable, and it selects the victims (the resting
orders the attacker chose to have matched).

**Fix, and it is a single change that covers both halves.** Restore
expiry-gated *permissionless* close with rent refunded to `marker.payer`, rather
than requiring `signer == payer`. That is what the v1 three-slot shape gave us;
§3.1 lost it as a side effect of dodging `ConstraintDuplicateMutableAccount`,
and the aliasing problem can be solved without it (the close instruction can
take the payer as a **read-only** refund target, since `close = ` needs the
lamport destination writable but the *authority* need not be the same account).
Separately, `verify_match_batch`'s caller should detect an already-initialised
marker and continue rather than failing the batch.

> **Resolved 2026-08-19 — enclave-only, and two things above were wrong.**
>
> **S-04 already removed the dangerous half.** `verify_match_batch` DERIVES
> `expiry_slot` rather than accepting it (`verify_match_batch.rs:83-102`), and
> its comment describes almost exactly this attack — a front-runner setting
> `expiry = slot + 1` so every settle fails `BatchValidityMarkerExpired`. That
> lever is gone. What survived is only the `init` collision, which S-04's
> comment explicitly notes it does not address.
>
> That makes **reconciliation** the right fix: a foreign marker for our root can
> only exist if a valid Groth16 proof for that exact root and config digest
> verified on-chain, and its TTL is derived, so it is functionally the marker we
> would have created — only `payer` differs. `settle/worker.rs` now continues
> against it instead of failing the batch.
>
> **The rent half was worse than written here.** Sweeper closes are packed into
> ONE atomic tx, so a single un-closable marker failed the whole chunk on every
> tick, forever — stranding the rent of every LEGITIMATE marker beside it, not
> just its own. The module header's claim that "a single stale root can never
> poison a packed close tx" was true only for markers that no longer EXIST.
> `marker_sweep.rs` now reads `marker.payer` and drops foreign markers.
>
> **The on-chain permissionless close was NOT taken.** v2's check is
> `dups.intersects(&MUT_MASK)` (`anchor-lang-2.0.0-rc.1/src/dispatch.rs:108`) —
> any duplicated position that is a `mut` field trips 2040, so the three-account
> shape proposed above would re-break exactly as it did during the port. The
> enclave fix makes it unnecessary.

> **Correction, 2026-08-18.** This section originally rated PS-02 **Low** and
> said "the batch still settles". That was wrong: it assumed the worker treats a
> failed Tx B as recoverable. It does not — the `?` propagates. Raised by
> CodeRabbit on PR #175 and confirmed by reading `settle/worker.rs`. The
> mistake is worth recording because it came from reasoning about the on-chain
> handler in isolation while the impact lived in the caller.

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
