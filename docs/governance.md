# Nyx — Governance & Authority Model

> **Status:** target model for a mainnet deployment. The live **devnet**
> deployment uses single keypairs for all authorities (fine for devnet, where
> we control the deploy). This document is the runbook for moving them onto a
> governance multisig before mainnet — **audit_1 F-03 + F-10**.
>
> For the TEE-key rotation ceremony (the attestation half of F-10) see
> **[`tee-attestation-flow.md` §5](tee-attestation-flow.md)** — it is *not*
> duplicated here. For why price fairness is deliberately TEE-trusted (the
> compensating-control context for this multisig) see **`CRYPTOGRAPHY.md` §2**.

---

## 0. TL;DR

There are **four** privileged authorities over a live Nyx deployment. Today
(devnet) each is a single keypair. The mainnet target is to put all four behind
one **Squads v4** M-of-N multisig, so no single key can freeze funds, hijack the
program, or rotate the TEE signer without a quorum that has independently
verified the enclave attestation.

| Authority | Controls | Set / rotated by | Devnet holder | Mainnet target |
|---|---|---|---|---|
| **Program upgrade authority** | Replacing the on-chain program bytecode (BPFLoaderUpgradeable) | `solana program set-upgrade-authority` | `~/.config/solana/id.json` | Squads vault PDA |
| **`VaultConfig.admin`** | `set_tee_pubkey` (TEE signer rotation), `set_protocol_config` | Fixed at `initialize` (no transfer ix — see §3) | `initialize` signer | Squads vault PDA |
| **`VaultConfig.root_key`** | `rotate_root_key` (self-signed), is the `create_wallet` owner | `initialize` param, then self-rotating | `root_key` param | Squads vault PDA (or a separate cold quorum) |
| **Phala compose-hash allowlist** | Which CVM image the KMS releases keys to | Phala Cloud dashboard | deploy team | deploy team (out of multisig — see §4) |

The point of F-10: **the program upgrade authority and `admin` are the two
single points of total compromise** (upgrade → arbitrary code incl. draining
custody; `admin` → rotate the TEE signer to an attacker-controlled key). A
single leaked key = game over. A 3-of-5 multisig raises that to "3 independent
signers colluding or compromised."

---

## 1. What each authority can actually do

- **Program upgrade authority** — the strongest. Can `solana program deploy
  --upgrade` a new `vault.so` with *any* logic (skip the ZK verifier, mint
  arbitrary notes, drain the token accounts). Nothing on-chain constrains a
  program upgrade beyond holding this key. This is why it must be the
  hardest-quorum authority.
- **`admin`** — rotates the TEE Ed25519 signer set (`set_tee_pubkey`) and sets
  the protocol config (`set_protocol_config`). A malicious `admin` can point
  `tee_pubkeys` at a key it controls, then forge settle payloads → **this is the
  F-10 attack the attestation gate (§5 of the attestation flow) closes.**
- **`root_key`** — the protocol "root" governance key. It is the `owner` that
  signs `create_wallet`, and it self-rotates via `rotate_root_key` (only the
  *current* `root_key` can install a successor — `admin` cannot override it).
  Distinct lifecycle from `admin`: rarely used, so a good candidate for a
  separate, colder quorum if you want operational separation.
- **Phala compose-hash allowlist** — deliberately *outside* the on-chain
  multisig. It governs which enclave image gets KMS keys; it is a Phala-dashboard
  action. The multisig's job is to *verify the attestation before trusting a
  key*, not to gate the image allowlist (see §4).

---

## 2. Recommended structure — one Squads v4 multisig

Use **[Squads v4](https://squads.so)** — the de-facto audited Solana multisig.
Its **vault PDA** is a normal `Pubkey`, so it drops in as `admin` / `root_key` /
upgrade authority with **zero program changes** (the vault already treats all
three as opaque pubkeys). Squads executes an arbitrary instruction by CPI with
its vault PDA as a signer, which is exactly what `set_tee_pubkey`,
`rotate_root_key`, and `initialize` need.

**Default:** one 3-of-5 multisig; its vault PDA is the upgrade authority +
`admin` + `root_key`.

**Optional separation** (recommended for a large deployment): a second,
higher-threshold / colder multisig for `root_key` and the upgrade authority
(rarely exercised, catastrophic if abused), leaving the day-to-day `admin`
(TEE rotation, which happens on every image upgrade) on the 3-of-5 operations
multisig. Pick the split before `initialize` — `admin` cannot be changed after
(§3).

Threshold guidance: **≥ 3-of-5** for operations; consider 4-of-7 for the
root/upgrade quorum. Signers on independent hardware wallets, geographically
and organizationally distinct (the attestation ceremony's independence
assumption in §5.2 of the attestation flow only holds if the signers really are
independent).

---

## 3. The F-03 interaction — `initialize` is bound to the upgrade authority

Audit F-03: on a freshly deployed program, whoever calls `initialize` first
becomes `admin` — a front-run. The fix (shipped) binds the mainnet `initialize`
to the **program upgrade authority**:

```
# mainnet Initialize (programs/vault/src/instructions/initialize.rs, no devnet-admin feature)
program:      Program<Vault>       constraint: program.programdata_address() == program_data
program_data: Account<ProgramData> constraint: program_data.upgrade_authority_address == admin
```

So `initialize` can only be called by the current upgrade authority. Two
consequences for the bootstrap order:

1. **There is no `set_admin` / `transfer_admin` instruction.** `admin` is fixed
   at `initialize` for the life of the config. The *only* way to make `admin`
   the multisig is to have the multisig (as upgrade authority) execute
   `initialize`. → **Transfer the upgrade authority to the multisig BEFORE
   calling `initialize`** (§4, step 3).
2. The dev/test/devnet build (`--features devnet-admin`) keeps the old
   plain-signer `initialize` (no ProgramData binding) — the litesvm harness
   loads the program non-upgradeably, and front-running isn't a threat where we
   control the deploy. This mirrors the F-01/F-02 gate: the guard rides the
   **mainnet** artifact only. (If you ever want a post-init admin handoff instead
   of this bootstrap order, a future `transfer_admin` ix gated on the current
   `admin` signer would be the clean addition — out of scope here.)

---

## 4. Mainnet bootstrap runbook (order matters)

Illustrated with Squads v4. `PROGRAM_ID` = the deployed `vault` program;
`VAULT_PDA` = the Squads multisig **vault** PDA (not the multisig account
itself).

```sh
# 1. Create the Squads multisig (UI or CLI). Record its VAULT PDA.
#    Fund the vault PDA with SOL (it is the fee-payer/rent-payer for the
#    instructions it will execute).

# 2. Deploy the MAINNET program artifact (no devnet-admin feature → F-01/F-02
#    backdoors absent, F-03 binding present). Deployer keypair is the
#    temporary upgrade authority.
cargo build-sbf --manifest-path programs/vault/Cargo.toml     # NO --features
solana program deploy target/deploy/vault.so --program-id <PROGRAM_KEYPAIR>

# 3. Transfer the upgrade authority to the multisig vault PDA. MUST happen
#    before initialize (F-03: the initialize signer must be the upgrade
#    authority, and we want that to be the multisig).
solana program set-upgrade-authority "$PROGRAM_ID" \
  --new-upgrade-authority "$VAULT_PDA"

# 4. From Squads, propose + execute `initialize` with the vault PDA as `admin`.
#    Accounts: admin = VAULT_PDA (signer, via Squads CPI), vault_config (init),
#    program = PROGRAM_ID, program_data = <PROGRAM_ID's ProgramData PDA>,
#    system_program. Args: tee_pubkey (the attested shard-0 signer), root_key
#    (VAULT_PDA, or the separate root quorum's vault PDA), num_trees (K).
#    → cfg.admin = VAULT_PDA. F-03 constraint passes (admin == upgrade authority).

# 5. Create the K per-shard trees (`initialize_tree` ×K) and the settle ALT,
#    then register + fund the full K-shard TEE signer set. TEE-key rotation
#    (set_tee_pubkey) runs through the ATTESTATION CEREMONY — see
#    tee-attestation-flow.md §5 (verify MRTD/compose-hash/report_data off-chain,
#    THEN the multisig signs). Never rubber-stamp a key (§5.2 there).
```

**Do NOT** call `initialize` with the deployer as admin and expect to hand off
later — there is no admin-transfer path (§3.1). Get the order right the first
time.

---

## 5. Attestation-gated TEE rotation (the other half of F-10)

`set_tee_pubkey` is `admin`-only on-chain. Under this governance model `admin`
is the multisig, and the multisig **must** run the attestation verification
before signing — this is the compensating control for the accepted
TEE-trusted-price decision (F-11) and the freeze/forge risk in F-10.

The full ceremony (fetch a fresh quote bound to the new pubkey via
`report_data`, verify Intel TCB cert chain + `mr_td` + the `rtmr3` compose-hash
event with `dstack-verifier`, cross-check the compose-hash against the deploy
commit, then each signer independently repeats it on distinct
hardware) is documented in **[`tee-attestation-flow.md` §5](tee-attestation-flow.md)**.
That verification is **off-chain by design** (§5.3 there: porting `dcap-qvl` to
BPF is the deferred v3 work, §11) — on mainnet the trust assumption is "the
multisig honestly does the off-chain verification," the same assumption every
TEE-on-Solana project uses today. **A multisig signature on `set_tee_pubkey` is
a verification claim, not a rubber-stamp.**

---

## 6. Verification — confirm the authorities are the multisig

```sh
# Upgrade authority == the multisig vault PDA:
solana program show "$PROGRAM_ID"        # "Authority" line must equal VAULT_PDA

# admin / root_key == the multisig vault PDA: read VaultConfig and compare.
# (SDK: read the VaultConfig account; admin is the first pubkey field,
#  root_key follows tee_pubkeys[MAX_TEE_KEYS]. See programs/vault/src/state.rs.)
```

Re-audit checklist item (audit_1): *"Admin/root/upgrade authority = multisig
(verify `solana program show`)"* — satisfied when all three above resolve to the
multisig vault PDA(s).

---

## 7. Threat coverage summary

| Threat | Single-key (today, devnet) | Multisig (F-10 target) |
|---|---|---|
| Leaked upgrade key → malicious program upgrade drains custody | total loss | needs quorum collusion |
| Leaked `admin` key → rotate TEE signer to attacker key → forge settles | total loss | needs quorum + defeats §5 attestation |
| `initialize` front-run installs attacker as `admin` (F-03) | possible pre-fix | closed — initializer bound to upgrade authority (§3) |
| Malicious TEE forges a settle payload | on-chain Ed25519 check + conservation proof bound it to no-inflation; price fairness TEE-trusted (F-11) | same + attestation-gated key set |

The multisig does **not** change the on-chain soundness guarantees (conservation
/ range / fee-floor are enforced by `VALID_MATCH_BATCH` regardless of who admin
is). It hardens the *authority* layer: it stops a single compromised key from
replacing the program or the trusted TEE signer.
