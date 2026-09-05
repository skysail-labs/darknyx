# Settlement amount-privacy soundness invariants

This is the compact, current invariant note referenced by
`circuits/templates/match_batch.circom`. It is not a migration tracker or an
implementation history. The circuit and `CRYPTOGRAPHY.md` §7.4 are the
authoritative protocol descriptions.

## 1. Threat model

The TEE supplies private note openings and match amounts, but the Groth16 proof
must prevent it from creating value, selecting an incorrect price quotient, or
choosing an arbitrary protocol fee. On-chain settlement trusts only a proof
against the committed verification key and the public batch inputs.

## 2. Integer interpretation inside BN254

Every note amount, trade amount, change amount, and fee amount is range-checked
to 64 bits. The conservation equations are:

```text
buyer_quote_input = trade_quote + buyer_quote_change + buyer_quote_fee
seller_base_input = trade_base + seller_base_change + seller_base_fee
```

Each right-hand side is smaller than `3 * 2^64`, far below the BN254 scalar
field modulus. Consequently, equality in the field is also equality over the
intended non-negative integers: modular wraparound cannot satisfy a false
conservation equation.

## 3. Scaled floor pricing

For positive `price_scale`, the circuit proves:

```text
trade_base * clearing_price = trade_quote * price_scale + price_remainder
0 <= price_remainder < price_scale
```

The quotient and bounded remainder uniquely imply:

```text
trade_quote = floor(trade_base * clearing_price / price_scale)
```

The multiplicands and intermediate values are range-constrained to the bit
widths used by the circuit comparators.

## 4. Exact fee quotient

Let `x = notional * fee_rate_bps`, `d = 10_000`, and `f` be the claimed fee.
The circuit proves both:

```text
f * d <= x
(f + 1) * d > x
```

The first inequality gives `f <= floor(x / d)` and the second gives
`f >= floor(x / d)`. Together they uniquely establish
`f = floor(x / d)`. All values and products are bounded within the comparator
width, so neither inequality can be satisfied through field wraparound.

## 5. Slot activity

An active match slot has positive trade base, clearing price, and derived quote
amount and must satisfy conservation, pricing, fee, mint, and output-binding
constraints. An inactive slot is canonical zero padding. This prevents a prover
from hiding unconstrained value in a padded slot or treating a zero trade as a
real match.

## 6. Change control

Any change to these invariants is a circuit change. Rebuild and commit the
Circom source, proving key, verification key, N=16 fixture, Rust/TypeScript
parity updates, and circuit tests atomically. External audit and ceremony gates
remain tracked under `audits/`; this note does not close them.

## 7. Verification anchors

- `circuits/templates/match_batch.circom`
- `CRYPTOGRAPHY.md` §7.4
- `programs/vault/src/zk/vk_match_batch_n16.rs`
- the match-batch proof and negative-soundness tests in the Rust and TypeScript
  suites

## 8. Why the fee inequalities are symmetric

For integer `q = floor(x / d)`, Euclidean division gives
`q*d <= x < (q+1)*d`. Conversely, if an integer `f` satisfies both inequalities
above, no integer smaller or larger than `q` can satisfy both. This is the
floor/ceiling argument cited by the circuit comment.
