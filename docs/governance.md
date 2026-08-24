# Darknyx — Governance & Authority Model

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

There are **four** privileged authorities over a live Darknyx deployment. Devnet
uses single keypairs. Mainnet deliberately uses **two** Squads v4 multisigs:
an operations 3-of-5 for routine protocol/market/TEE-key changes and a cold
root/upgrade 4-of-7 for catastrophic authority. No single key can freeze
funds, replace the program, or rotate a trusted TEE signer.

| Authority | Controls | Set / rotated by | Devnet holder | Mainnet target |
|---|---|---|---|---|
| **Program upgrade authority** | Replacing the on-chain program bytecode (BPFLoaderUpgradeable) | `solana program set-upgrade-authority` | `~/.config/solana/id.json` | Cold root/upgrade 4-of-7 vault PDA |
| **`VaultConfig.admin`** | TEE signer rotation, global fee config, Merkle-tree and `MarketConfig` administration | `operations_admin` argument at `initialize` (no transfer ix) | `initialize` signer | Operations 3-of-5 vault PDA |
| **`VaultConfig.root_key`** | `rotate_root_key` (self-signed) | `initialize` param, then self-rotating | `root_key` param | Cold root/upgrade 4-of-7 vault PDA |
| **Phala compose-hash allowlist** | Which CVM image the KMS releases keys to | Phala Cloud dashboard | deploy team | deploy team (out of multisig — see §4) |

The point of F-10/N-19: **the program upgrade authority and `admin` are the two
single points of total compromise** (upgrade → arbitrary code incl. draining
custody; `admin` → rotate the TEE signer to an attacker-controlled key). A
single leaked key = game over. Split quorums separate frequent operations from
the colder authority that can replace code or the protocol root.

The operations admin also holds the **market kill switch**
(`update_market_config` → `enabled = false`). Read **§7** before reaching for it
during an incident: it stops the market being *admitted to and matched*, but an
already-verified batch keeps settling until its marker expires (≤ 300 slots).
That bound is deliberate — aborting mid-flight would strand collateral the batch
has already locked on-chain.

---

## 1. What each authority can actually do

- **Program upgrade authority** — the strongest. Can `solana program deploy
  --upgrade` a new `vault.so` with *any* logic (skip the ZK verifier, mint
  arbitrary notes, drain the token accounts). Nothing on-chain constrains a
  program upgrade beyond holding this key. This is why it must be the
  hardest-quorum authority.
- **`admin`** — the operations authority. It rotates the TEE Ed25519 signer set
  (`set_tee_pubkey`), sets global fee config (`set_protocol_config`), and
  initializes/updates/pauses mint-pair `MarketConfig` PDAs. A malicious admin
  can point `tee_pubkeys` at a key it controls, then forge settle payloads → **this is the
  F-10 attack the attestation gate (§5 of the attestation flow) closes.**
- **`root_key`** — the protocol "root" governance key. It is the `owner` that
  is a protocol governance authority and self-rotates via `rotate_root_key` (only the
  *current* `root_key` can install a successor — `admin` cannot override it).
  Distinct lifecycle from `admin`: rarely used, so a good candidate for a
  separate, colder quorum if you want operational separation.
- **Phala compose-hash allowlist** — deliberately *outside* the on-chain
  multisig. It governs which enclave image gets KMS keys; it is a Phala-dashboard
  action. The multisig's job is to *verify the attestation before trusting a
  key*, not to gate the image allowlist (see §4).

---

## 2. Required structure — split Squads quorums

Use **[Squads v4](https://squads.so)** — the de-facto audited Solana multisig.
Each Squads **vault PDA** is a normal `Pubkey`, so it can sign the corresponding
vault instructions by CPI:

- **Operations: 3-of-5.** Stored as `VaultConfig.admin`. It handles TEE-key
  rotations, fees, tree initialization, and market initialization/updates.
- **Cold root/upgrade: 4-of-7.** Installed as both program upgrade authority
  and `VaultConfig.root_key`. It executes the one-time mainnet `initialize`
  because that entrypoint is bound to the current upgrade authority.

The on-chain initializer rejects an operations admin equal to the root key and,
in a mainnet build, rejects an operations admin equal to the upgrade-authority
signer. Signers should use independent hardware and independent attestation
verification; shared signers across the two groups weaken the intended split.

---

## 3. The F-03 interaction — `initialize` is bound to the upgrade authority

Audit F-03: on a freshly deployed program, whoever calls `initialize` first
becomes `admin` — a front-run. The fix (shipped) binds the mainnet `initialize`
to the **program upgrade authority**:

```
# mainnet Initialize (programs/vault/src/instructions/initialize.rs, no devnet-admin feature)
program:      Program<Vault>       constraint: program.programdata_address() == program_data
program_data: Account<ProgramData> constraint: program_data.upgrade_authority_address == upgrade_authority
```

So `initialize` can only be called by the current upgrade authority. Two
consequences for the bootstrap order:

1. **There is no `set_admin` / `transfer_admin` instruction.** `admin` is fixed
   at `initialize`. The cold upgrade multisig executes `initialize` while the
   distinct operations vault PDA is passed as `operations_admin`. Transfer the
   upgrade authority to the cold multisig before initialization.
2. The dev/test/devnet build (`--features devnet-admin`) keeps the old
   plain-signer `initialize` (no ProgramData binding) — the litesvm harness
   loads the program non-upgradeably, and front-running isn't a threat where we
   control the deploy. This mirrors the F-01/F-02 gate: the guard rides the
   **mainnet** artifact only. (If you ever want a post-init admin handoff instead
   of this bootstrap order, a future `transfer_admin` ix gated on the current
   `admin` signer would be the clean addition — out of scope here.)

---

## 4. Mainnet bootstrap runbook (order matters)

Illustrated with Squads v4. `PROGRAM_ID` is the deployed vault program;
`OPS_VAULT` and `COLD_VAULT` are the two Squads **vault PDAs** (not the
multisig account addresses).

```sh
# 1. Create operations 3-of-5 and cold root/upgrade 4-of-7 Squads multisigs.
#    Record and fund OPS_VAULT and COLD_VAULT.

# 2. Deploy the MAINNET program artifact (no devnet-admin feature → F-01/F-02
#    backdoors absent, F-03 binding present). Deployer keypair is the
#    temporary upgrade authority.
cargo build-sbf --manifest-path programs/vault/Cargo.toml     # NO --features
solana program deploy target/deploy/vault.so --program-id <PROGRAM_KEYPAIR>

# 3. Transfer the upgrade authority to the cold vault PDA. MUST happen
#    before initialize (F-03: the initialize signer must be the upgrade
#    authority).
solana program set-upgrade-authority "$PROGRAM_ID" \
  --new-upgrade-authority "$COLD_VAULT"

# 4. From the cold Squads, propose + execute `initialize`.
#    Accounts: upgrade_authority = COLD_VAULT (signer), vault_config (init),
#    program = PROGRAM_ID, program_data = <PROGRAM_ID's ProgramData PDA>,
#    system_program. Args: operations_admin = OPS_VAULT,
#    tee_pubkeys = exactly K independently attested shard signers,
#    root_key = COLD_VAULT, num_trees = K.
#    → cfg.admin = OPS_VAULT while root/upgrade remain COLD_VAULT.

# 5. Through the operations Squads, create K trees (`initialize_tree` ×K),
#    initialize each mint-pair MarketConfig, set the global fee config, and
#    create the settle ALT. Later TEE-key rotation
#    (set_tee_pubkey) runs through the ATTESTATION CEREMONY — see
#    tee-attestation-flow.md §5 (verify MRTD/compose-hash/report_data off-chain,
#    THEN the multisig signs). Never rubber-stamp a key (§5.2 there).
```

**Do NOT** initialize with a deployer key or reuse `COLD_VAULT` as
`operations_admin`; there is no admin-transfer path. Get the split right once.

---

## 5. Attestation-gated TEE rotation (the other half of F-10)

`set_tee_pubkey` is operations-admin-only on-chain. The operations multisig
**must** run the attestation verification before signing — this is the
compensating control for the accepted
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
# Upgrade authority == COLD_VAULT:
solana program show "$PROGRAM_ID"

# Read VaultConfig and compare admin == OPS_VAULT, root_key == COLD_VAULT,
# num_tee_keys == num_trees, with every key non-default and unique.
# (SDK: read the VaultConfig account; admin is the first pubkey field,
#  root_key follows tee_pubkeys[MAX_TEE_KEYS]. See programs/vault/src/state.rs.)

# Read every MarketConfig and verify the mint pair, mint decimals, nonzero
# price_scale/tick/minimum size, bounded breaker, and intended enabled state.
```

N-19 is satisfied only after the 3-of-5 and 4-of-7 execution paths are rehearsed
and every signer independently verifies the proposed TEE attestation before a
rotation.

---

## 7. What the market kill switch actually promises

`update_market_config` can set `MarketConfig.enabled = false`. It is the fastest
governance lever available, so it is worth stating precisely what it does and
does not stop — the semantics are load-bearing during an incident, and until now
they were unwritten.

**`disabled` means "stop admitting and matching". It does not mean "stop
settling".**

Three layers respond, on three different timescales:

| Layer | Effect of `enabled = false` | Timing |
|---|---|---|
| TEE governance monitor (`main.rs::spawn_governance_monitor`) | Any `MarketConfig` drift — including `enabled` — fails `permits_trading`, so the trading gate pauses. New place/modify and matching stop; cancel and reconciliation stay available. | Within one refresh, ≤ `GOVERNANCE_REFRESH_INTERVAL` (60 s) |
| `verify_match_batch` | `require!(market.enabled, VaultError::MarketDisabled)`. No **new** batch can be admitted on-chain, whatever the TEE believes. | Immediate, next slot |
| `tee_forced_settle_batched` | Reads **no** `MarketConfig` at all. Batches already verified before the flip keep settling. | Until the batch's marker expires — bounded by `MAX_BATCH_VALIDITY_MARKER_TTL_SLOTS` = **300 slots** (~2 min) |

So the worst-case window between disabling a market and the last possible
settlement on it is the remaining life of any already-written
`BatchValidityMarker`: at most 300 slots, and normally far less because the
settle worker drives a batch through within seconds of verifying it.

**This is deliberate, not an oversight.** By the time `verify_match_batch` has
succeeded, that batch's inputs are already pinned on-chain: `NoteLock` PDAs are
held, the `BatchValidityMarker` is written, and the notes are unspendable through
`withdraw` or `merge` until they expire. Aborting settlement at that point would
not protect anyone — it would strand real user collateral in a locked state with
no path to release before `MAX_LOCK_TTL_SLOTS`, converting a governance pause
into a user-funds freeze. Letting an already-verified batch complete returns the
collateral to its owners as outputs, which is the outcome a disable is trying to
reach in the first place.

**Operationally**, this means a disable is a clean stop for *new* risk and a
short, bounded drain for *existing* risk. If an incident requires that in-flight
batches never land, `enabled = false` is not the tool — the marker window has to
run out, or the TEE signer set has to be rotated out of
`vault_config.tee_pubkeys` so the settle transaction can no longer be authorized
at all. Rotation is the harder lever and the one that actually stops a settle
mid-flight; it also strands the locked collateral until expiry, which is why it
is the incident-only option.

> Reopen this as a code item only if governance decides in-flight batches must
> abort. That would require `tee_forced_settle_batched` to take and check
> `MarketConfig`, which costs an account in the settle transaction — see
> `CRYPTOGRAPHY.md` §9, where Tx D has ~123 bytes of headroom — and an explicit
> decision about what happens to the collateral it leaves locked.

---

## 8. Threat coverage summary

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
