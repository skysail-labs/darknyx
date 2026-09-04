# Local Surfpool + dstack matrix runbook

This is the operator runbook for Darknyx's complete local protocol matrix. It
runs the production `darknyx-tee` process against a pinned Surfpool validator
and the pinned dstack v0.5.9 simulator. Every case uses a new empty ledger,
real circuit witnesses and proofs, and the fingerprinted vault SBF.

No command in this runbook starts a Phala CVM or contacts devnet. A pass is
local integration evidence, not evidence for TDX isolation, Intel DCAP, Phala
KMS, RA-TLS passthrough, or real-cluster confirmation/finality latency.

## 1. Know the six cases and the pass condition

`all` runs these cases in order:

1. `deposit-withdraw` — deposit, spend, withdraw, and lock-expiry lifecycle.
2. `merge` — a real K=2 merge proof and on-chain merge.
3. `settle` — one crossing match, settlement, seed-plus-chain recovery, cold TEE
   restart, exact K-shard reconciliation, and simulator-quote rejection.
4. `multimatch` — four matches proved as one padded N=16 batch and settled.
5. `self-trade` — self-trade policy and the expected no-match boundary.
6. `merge-then-order` — merge notes, prove an order over the merged output, and
   settle it.

The run is successful only when it exits zero and ends with:

```text
PHASE3_MATRIX_PASS cases=6 mode=all
```

Each case must also print `PHASE3_CASE_PASS`, archive a `phase3-result.json`
whose `result` is `pass`, and record `clean` teardown for both supervisors.

## 2. Host prerequisites

Run everything from the repository root. The current local recipe is qualified
on Apple Silicon macOS.

```sh
command -v node npm cargo rustup solana solana-keygen jq curl git
node --version                   # Node 22 is the CI baseline
solana --version
npm install                     # use npm ci on a clean checkout
git lfs pull                    # proving zkeys must be real LFS objects
```

Confirm the required circuit artifacts are hydrated. A Git LFS pointer is a
small text file and will otherwise fail much later during TEE boot.

```sh
for name in valid_deposit valid_input valid_spend match_batch_n16 \
            valid_merge_k2 valid_merge_k4; do
  wasm="circuits/build/$name/circuit_js/circuit.wasm"
  zkey="circuits/build/$name/circuit_final.zkey"
  test -f "$wasm" || { echo "missing $wasm"; exit 1; }
  test "$(wc -c < "$zkey")" -gt 100000 \
    || { echo "$zkey is missing or is an LFS pointer"; exit 1; }
done
```

## 3. Optional but recommended: put build and validator state on an SSD

Cargo/Solana builds need normal Unix filesystem behavior. Do not point Cargo
directly at an ExFAT volume. On an ExFAT SSD, create a grow-on-demand,
case-sensitive APFS sparsebundle instead. This does not reformat the SSD and a
200 GB maximum image consumes only the bytes actually written.

The following is the setup used with the `kingston2TB` volume. Run the creation
command only once:

```sh
test -d /Volumes/kingston2TB
hdiutil create \
  -size 200g \
  -type SPARSEBUNDLE \
  -fs 'Case-sensitive APFS' \
  -volname DarknyxBuild \
  /Volumes/kingston2TB/DarknyxBuild.sparsebundle
```

Mount it for each work session:

```sh
hdiutil attach -nobrowse /Volumes/kingston2TB/DarknyxBuild.sparsebundle
test -d /Volumes/DarknyxBuild
mkdir -p /Volumes/DarknyxBuild/tmp
```

Before moving existing state, stop every local process:

```sh
bash scripts/surfpool/local-tee.sh down || true
bash scripts/surfpool/foundation.sh down || true
```

Move the two gitignored workspaces once. Do not run `mv` again when the
symlinks already exist.

```sh
if test ! -L target; then
  if test -e target; then
    test ! -e /Volumes/DarknyxBuild/darknyx-monorepo-target
    mv target /Volumes/DarknyxBuild/darknyx-monorepo-target
  else
    mkdir -p /Volumes/DarknyxBuild/darknyx-monorepo-target
  fi
  ln -s /Volumes/DarknyxBuild/darknyx-monorepo-target target
fi
if test ! -L .surfpool; then
  if test -e .surfpool; then
    test ! -e /Volumes/DarknyxBuild/darknyx-monorepo-surfpool
    mv .surfpool /Volumes/DarknyxBuild/darknyx-monorepo-surfpool
  else
    mkdir -p /Volumes/DarknyxBuild/darknyx-monorepo-surfpool
  fi
  ln -s /Volumes/DarknyxBuild/darknyx-monorepo-surfpool .surfpool
fi
```

Verify that both paths resolve onto the APFS image:

```sh
readlink target
readlink .surfpool
df -h . /Volumes/DarknyxBuild
```

Keep the image mounted while Cargo, Surfpool, or the TEE is running. A broken
`target` or `.surfpool` symlink after reconnect means the sparsebundle has not
been mounted yet.

## 4. Prepare the pinned Surfpool binary

If `.surfpool/bin/surfpool` already exists, verify it against `pin.json`:

```sh
set -euo pipefail
test "$(.surfpool/bin/surfpool --version)" \
  = "$(jq -r .reportedVersion scripts/surfpool/pin.json)"
test "$(shasum -a 256 .surfpool/bin/surfpool | awk '{print $1}')" \
  = "$(jq -r '.artifacts["darwin-arm64"].binarySha256' \
      scripts/surfpool/pin.json)"
```

When it is missing, build the immutable pinned revision from source. The
downloaded Studio input is independently checksum-pinned; do not build moving
`main` or accept a mutable `latest` asset.

```sh
rustup toolchain install 1.95.0 --profile minimal
mkdir -p .surfpool/bin .surfpool/source

repo=$(jq -r .repository scripts/surfpool/pin.json)
commit=$(jq -r .commit scripts/surfpool/pin.json)
git -C .surfpool/source init
git -C .surfpool/source remote get-url origin >/dev/null 2>&1 \
  || git -C .surfpool/source remote add origin "https://github.com/$repo.git"
git -C .surfpool/source fetch --depth 1 origin "$commit"
git -C .surfpool/source checkout --detach FETCH_HEAD
test "$(git -C .surfpool/source rev-parse HEAD)" = "$commit"

studio_url=$(jq -r .studioUi.url scripts/surfpool/pin.json)
studio_sha=$(jq -r .studioUi.sha256 scripts/surfpool/pin.json)
curl --fail --silent --show-error --location "$studio_url" \
  --output .surfpool/studio-dist.zip
test "$(shasum -a 256 .surfpool/studio-dist.zip | awk '{print $1}')" \
  = "$studio_sha"

STUDIO_UI_DIST="$PWD/.surfpool/studio-dist.zip" \
  cargo +1.95.0 build \
    --manifest-path .surfpool/source/Cargo.toml \
    --release --locked --features supervisor_ui --features version_check
cp .surfpool/source/target/release/surfpool .surfpool/bin/surfpool
chmod 0755 .surfpool/bin/surfpool
.surfpool/bin/surfpool --version
```

Source builds need more space and time than merely running the matrix. With the
SSD arrangement above, `.surfpool/source/target` is also external.

## 5. Prepare the pinned dstack simulator

The supervisor accepts only the pinned v0.5.9 commit:

```sh
export DSTACK_REPO="$PWD/dstack"
test "$(git -C "$DSTACK_REPO" rev-parse HEAD)" \
  = 282eeb27d22d8f091ad0fa5a90e638f85cf68751
```

For a new checkout:

```sh
git clone https://github.com/Dstack-TEE/dstack.git "$DSTACK_REPO"
git -C "$DSTACK_REPO" checkout --detach \
  282eeb27d22d8f091ad0fa5a90e638f85cf68751
```

Build the simulator when its executable is missing:

```sh
DSTACK_REPO="$DSTACK_REPO" bash scripts/dstack-simulator-start.sh --build
test -x "$DSTACK_REPO/sdk/simulator/dstack-simulator"
```

The simulator implements the guest API shape and deterministic development
keys. It does not emulate TDX, DCAP, or Phala KMS.

## 6. Build the two Darknyx binaries

Set external compiler temporary storage for every large build when using the
SSD setup:

```sh
export TMPDIR=/Volumes/DarknyxBuild/tmp
```

Build the fingerprinted devnet-admin vault SBF and optimized production TEE:

```sh
bash scripts/build-vault-sbf.sh devnet-admin
cargo build --release --locked -p darknyx-tee
```

Verify the exact prerequisites the supervisors will consume:

```sh
test -f target/deploy/vault.so
test -f target/deploy/vault.so.fingerprint
test -x target/release/darknyx-tee
test -x .surfpool/bin/surfpool
test -x "$DSTACK_REPO/sdk/simulator/dstack-simulator"
```

## 7. Establish a clean starting boundary

```sh
bash scripts/surfpool/local-tee.sh down || true
bash scripts/surfpool/foundation.sh down || true
node scripts/surfpool/ports-closed.mjs \
  127.0.0.1 18080 18899 18900 19488
```

If this reports a live listener, identify and stop it. Do not kill an arbitrary
PID without first confirming that it belongs to Surfpool, dstack, or
`darknyx-tee`.

## 8. Run and observe the full matrix

Run with `pipefail` so logging cannot hide the matrix exit status:

```sh
set -o pipefail
TMPDIR=/Volumes/DarknyxBuild/tmp \
DSTACK_REPO="$PWD/dstack" \
  bash scripts/surfpool/local-tee-matrix.sh all \
  2>&1 | tee .surfpool/local-matrix.log
```

The matrix normally needs only a few minutes after its binaries are built.
Proof-backed cases can be quiet while Ark is proving; silence alone is not a
hang.

In a second terminal, follow progress with:

```sh
tail -f .surfpool/local-matrix.log
```

Or show only lifecycle markers:

```sh
rg 'PHASE3_(CASE_START|CASE_PASS|MATRIX_PASS)' \
  .surfpool/local-matrix.log
```

Run a smaller selection while diagnosing a failure:

```sh
bash scripts/surfpool/local-tee-matrix.sh smoke
bash scripts/surfpool/local-tee-matrix.sh settle
bash scripts/surfpool/local-tee-matrix.sh multimatch
```

Do not substitute a selected case for `all` when claiming complete local
matrix coverage.

## 9. Verify evidence and teardown

First require the final pass marker and closed ports:

```sh
tail -1 .surfpool/local-matrix.log \
  | grep -Fx 'PHASE3_MATRIX_PASS cases=6 mode=all'
node scripts/surfpool/ports-closed.mjs \
  127.0.0.1 18080 18899 18900 19488
```

Inspect all six result manifests:

```sh
find .surfpool/local-tee/evidence \
  -mindepth 2 -maxdepth 2 -name phase3-result.json -print0 \
  | xargs -0 jq -r '[.flow,.result,.realProofs] | @tsv' \
  | sort
```

Every current matrix teardown file must contain exactly `clean`:

```sh
for flow in deposit-withdraw merge settle multimatch self-trade \
            merge-then-order; do
  grep -Fx clean \
    ".surfpool/local-tee/evidence/phase3-$flow/teardown-status"
  grep -Fx clean \
    ".surfpool/foundation/evidence/phase3-$flow/teardown-status"
done
```

Extract settlement metrics without mistaking SDK wall-clock time for proving
time:

```sh
rg 'prove breakdown|settlement benchmark record|settle Tx D confirmed' \
  .surfpool/local-tee/evidence/phase3-*/tee.log \
  .surfpool/local-tee/evidence/phase3-*/tee.before-restart.log
```

Evidence is intentionally local and gitignored. Do not commit logs, generated
keys, ledgers, or `.surfpool/local-tee/current/env.sh`.

## 10. Stop early or recover after an interruption

The matrix installs an exit/signal cleanup trap. If the shell or host dies,
run the supervisors explicitly:

```sh
bash scripts/surfpool/local-tee.sh down || true
bash scripts/surfpool/foundation.sh down || true
node scripts/surfpool/ports-closed.mjs \
  127.0.0.1 18080 18899 18900 19488
```

If an incomplete `current/` directory remains after processes are confirmed
stopped, run the corresponding `down` command again so evidence is archived
and ephemeral keys are removed. Do not manually copy `current/` into evidence.

## 11. Unmount the external build image

Only after teardown proves all processes stopped:

```sh
hdiutil detach /Volumes/DarknyxBuild
```

The repository's symlinks will be intentionally broken until the next
`hdiutil attach`. Eject the physical Kingston SSD only after detaching the APFS
image.
