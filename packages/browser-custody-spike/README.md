# Darknyx browser custody spike

This package is a decision-grade prototype, not a production wallet. It tests
the browser branch of D1 in `docs/darknyx-client-design-record.md`:

- a 64-byte master seed is generated and held only inside a Worker during the
  normal flow;
- WebAuthn PRF plus HKDF derives a non-extractable AES-256-GCM wrapping key;
- IndexedDB persists only authenticated ciphertext and public wrapping
  metadata;
- explicit lock, inactivity lock, Worker termination, tamper rejection, and
  unsupported-PRF failure are exercised;
- the existing portable master-seed backup v2 format is exported and restored
  in the Worker with scrypt N=2^17;
- a deliberate same-origin attack proves the trust-model ceiling: after the
  user approves a WebAuthn assertion, arbitrary same-origin JavaScript can read
  IndexedDB and use the PRF result to decrypt the seed.

Run on stable Chrome:

```sh
npm -w @darknyx/browser-custody-spike test
```

The runner uses Chrome DevTools' virtual WebAuthn authenticator twice: once
with PRF support and once without it. This validates protocol behavior and
automation, not physical authenticator/browser compatibility. Real-device
qualification and wallet-extension behavior under COOP/COEP remain separate
manual gates.

The normal API deliberately exposes no generic `sign(bytes)`, no raw seed, and
no raw PRF result. `testOnlyFingerprint` and `simulateSameOriginCompromise`
exist solely to make the spike's positive and adversarial assertions measurable;
neither belongs in a production client package.
