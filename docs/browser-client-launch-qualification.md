# Browser client launch qualification

Status: **implementation stack complete; external launch evidence open.**

This record prevents locally passing emulation from being mistaken for a public
release decision. Each row needs attached environment/version details, raw
results, an owner, and an explicit pass before a release candidate can ship.

| Gate                    | Required evidence                                                                                                                                                                                                       | Current state |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Physical passkeys       | Provision, lock, unlock, backup and restore on Safari/macOS Touch ID, Windows Hello, one roaming FIDO2 key, and an unsupported PRF authenticator that fails closed                                                      | Open          |
| Wallets under isolation | Phantom plus one other Wallet Standard implementation connect and sign bounded deposit/withdraw/merge transactions under production COOP/COEP/CSP headers                                                               | Open          |
| x86 proving             | Warm/cold p50/p95/p99 and RSS for all six circuits on the minimum supported x86 machine; no circuit breaches the accepted UX envelope                                                                                   | Open          |
| Live venue              | Finalized governance + DCAP boot, deposit, order, fill, ambiguous reconnect, exact withdrawal, consolidation and seed-plus-chain recovery against a digest-pinned CVM                                                   | Open          |
| Account isolation       | Exercise the encrypted reference resolver or a managed replacement against a live CVM: restart recovery, concurrent provisioning, capacity/admission limits and operator access without exposing long-lived credentials | Open          |
| Host release            | Content-hashed assets, signed artifact envelope, reviewed public release pins, TLS/HSTS, no source maps/secrets, headers captured from the deployed origin                                                              | Open          |
| Security/legal          | Focused hostile-frontend, dependency/supply-chain and session-broker review; snarkjs GPL-3.0 distribution obligations resolved                                                                                          | Open          |
| Recovery drill          | Lost browser state restored from backup plus finalized chain; old account/order state reaches an explicit terminal outcome                                                                                              | Open          |
| MM selection integrity  | Threat model records that a compromised enclave can repeatedly select a colluding MM; published per-MM execution-quality statistics are live as the compensating control                                                | Open          |

Local implementation evidence currently available:

- browser unit, custody and six-circuit prover integrations under Chrome 151;
- responsive 375/768/1280 product render checks;
- release-host tests for exact public pins, CSP/Trusted Types, COOP/COEP,
  immutable/no-store caching, same-origin enforcement, signed cookie flags and
  rejection of shared CVM account identities.

The release owner must record dated evidence beneath this table or link a
versioned report before changing a row to Passed. A CI badge or an emulator-only
result is not sufficient for a physical-device or live-infrastructure gate.

After a CPU-CVM Live venue or Account isolation run, stop every billable CVM
and unset exported bootstrap credentials. Never leave a billable CPU CVM
running. Do **not** stop an on-demand GPU CVM: Phala permanently deallocates it
and forfeits the remaining prepaid window.
