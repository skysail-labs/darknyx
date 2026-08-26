# Darknyx protocol fee collector

This is an operator-only recovery tool, not a trader dependency or CVM service.
It reconstructs protocol-owned fee-note openings from finalized vault history
after the TEE journal and every online note cache have been lost.

The collector pairs each finalized `verify_match_batch` Tx B record with Tx D
settlements by recomputing the depth-four batch root from the public settlement
payload and inclusion proof. It decrypts the fixed N=16 amount bundle with the
backed-up epoch key, re-derives each fee inner, and retains a note only when the
recomputed commitment equals the finalized Tx D commitment and event leaf.
Failed or absent Tx Ds therefore never create phantom fee inventory.

Epoch keys live in a versioned AES-256-GCM file under the fixed
`scrypt-n17-r8-p1-v1` profile. Commands never print a key or recovered opening;
recovered inventories are separately encrypted at rest. The process holding an
unlocked keyring is the in-memory trust boundary.

The operational choreography, backup/rotation rules, and command examples are
in [`docs/protocol-fee-recovery-runbook.md`](../../docs/protocol-fee-recovery-runbook.md).
