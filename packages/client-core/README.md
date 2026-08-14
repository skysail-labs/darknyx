# Darknyx client core

This package is the platform-neutral boundary for the trader product. It does
not contain browser custody, proving, Solana wallet code, or UI components.

The public entry point exposes only aggregate balances, proof readiness, typed
intent submission, and the encrypted-vault lifecycle. Secret-bearing adapters
live behind `@darknyx/client-core/internal`. In particular, page code receives
no raw seed, witness, decrypted note record, generic `sign(bytes)`, or arbitrary
`prove` capability.

The intent coordinator also pins settlement-safe failure behavior:

- no ready cached proof means no authorization and no transport call;
- local authorization failure releases the reservation;
- definitive venue rejection releases it;
- ambiguous transport outcomes keep it reserved for reconciliation;
- a failed local release also remains reserved and becomes reconciliation work.

This is the bottom layer of the browser-product PR stack. Later layers implement
the internal ports without widening the public surface.
