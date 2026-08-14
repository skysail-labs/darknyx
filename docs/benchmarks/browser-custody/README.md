# Browser custody qualification

This directory holds retained evidence for packaging decision D1 in
`docs/darknyx-client-design-record.md`. The decision-grade prototype formerly
lived in `packages/browser-custody-spike`; it was removed on 2026-08-15 after
its selected design and still-required regressions landed in
`packages/browser-client`. Git history preserves the original harness.

The first retained run is
[`results/2026-08-10-apple-m3-chrome.json`](results/2026-08-10-apple-m3-chrome.json).
It used headless Chrome 151 on the Apple M3 development host. Treat the virtual
authenticator results as mechanism evidence, not a physical-device support
claim.

## What the spike decides

It answers whether a hosted Darknyx client can keep its 64-byte note credential
encrypted at rest behind a user-verified WebAuthn PRF credential while normal
key use stays in a Worker. It also makes the browser trust ceiling measurable:
arbitrary same-origin JavaScript is allowed to run the adversarial path and is
expected to recover the seed after the virtual user approves WebAuthn.

That negative test is intentional. WebAuthn PRF protects a copied IndexedDB
record and requires user verification to unwrap it; it does not turn a hosted
origin into a signed native execution boundary.

## Retained spike coverage

The Chrome runner checks:

- provision, explicit lock/unlock, inactivity lock, and Worker termination;
- AES-GCM tamper rejection and a non-extractable HKDF-derived wrapping key;
- ciphertext-only IndexedDB persistence;
- browser export and import of the SDK's master-seed backup v2 envelope;
- browser-produced backup opened by Node and Node-produced backup opened by the
  browser, preventing a self-consistent format drift;
- fail-closed behavior when the authenticator does not support WebAuthn PRF;
- COOP/COEP isolation, active Trusted Types enforcement, and absence of
  service-worker registrations in the harness;
- the deliberate same-origin compromise described above.

The final prototype source is retained in Git at commit `9b2ab55`; check out
that revision to reproduce the historical harness. Current production
regression coverage runs against the code that ships:

```sh
npm -w @darknyx/browser-client run test:custody
```

The production runner uses Chrome DevTools virtual authenticators with and
without PRF support. It does not repeat the deliberate same-origin compromise:
that successful attack established the accepted hosted-browser trust ceiling
and is retained as decision evidence, not as a property of shipping code. The
runner does not qualify physical passkeys, platform-authenticator recovery, or
wallet extensions.

## Remaining product gates

Before browser custody is a launch default:

1. Run a physical matrix on stable Chrome and Edge (Windows Hello, Touch ID,
   Android passkey, and at least one roaming FIDO2 key). Record PRF support,
   credential-sync behavior, cancellation, device loss, and recovery.
2. Test Phantom and the selected wallet-adapter flow with
   `COOP: same-origin` / `COEP: require-corp`; this is I6 and remains open.
3. Ship a dedicated origin with no third-party script, strict CSP and Trusted
   Types, pinned dependencies/artifacts, and an independently reviewed update
   and rollback design. Do not register a service worker until rollback is
   solved.
4. Give backup export/import an explicit progress UI. On the first Apple M3
   headless-Chrome run, scrypt N=2^17 took roughly 13 seconds in each direction
   while running off the main thread.
5. Perform the focused same-origin/XSS and supply-chain review. If the accepted
   threat model requires protection from malicious frontend delivery, choose
   the Tauri implementation of the same vault contract.

## Native fallback, precisely

In the Tauri branch, the “native vault” is normally a Rust module in the signed
Tauri host process. The WebView invokes typed internal commands; the seed lives
in Rust/OS-protected storage and never crosses into page JavaScript. It is not a
localhost HTTP daemon. A separate background process is needed only for an
agent-plus-browser-extension product, and would communicate through native
messaging or authenticated OS IPC.
