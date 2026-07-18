# Pyth accumulator (PNAU) wire format + Merkle inclusion — confirmed spec

> Phase-0 research notes for **C-05 / A-2** (bind the oracle price to the
> guardian-signed Pyth Merkle accumulator root). Every byte-level claim below
> was confirmed against the **`pythnet-sdk` source** (`pyth-network/pyth-crosschain`,
> `main`) *and* empirically validated against a real Hermes SOL/USD update — a
> throwaway parser reproduced the guardian-signed Merkle root from
> `(message ‖ proof)` and decoded `ema_price` byte-identically to Hermes's JSON
> `parsed[0].ema_price`, consuming the buffer exactly (1311/1311 bytes).
>
> Do not "simplify" any of this without re-confirming against source + the
> fixture — the sort/prefix/truncation/endianness details are exactly where a
> silent false-accept hides.

## Why this exists (the finding)

`crates/darknyx-tee/src/oracle/vaa.rs` verifies the Wormhole guardian ECDSA
signatures over the VAA body, but **never proves the price is included under the
signed Pyth Merkle root**. Worse, the price actually used (`ema_price`) is read
from Hermes's **JSON `parsed[]`** (`hermes.rs`), not extracted from the signed
binary at all — so it is doubly Hermes-trusted. A malicious Hermes (or a MITM
without RA-TLS) could serve a genuine, correctly-signed VAA next to a fabricated
price. C-05 closes this at the TEE trust boundary: parse the accumulator update,
verify each consumed price message's Merkle inclusion under the VAA-attested
root, and use the **binary-proven** message as the price source.

## Source anchors (pythnet-sdk, `pythnet/pythnet_sdk/src/`)

| Fact | File | Note |
|---|---|---|
| Custom serde format: seqs/str/bytes use a **`u8`** length prefix; enum variant = **`u8`**; ints use a generic `ByteOrder` param | `wire/ser.rs` | `serialize_seq` → `u8::try_from(len)` (max 255) |
| `AccumulatorUpdateData::try_from_slice` uses `from_slice::<byteorder::BE>` | `wire.rs:63` | **the production format is BIG-ENDIAN** |
| `WormholeMessage::try_from_bytes` uses `from_slice::<byteorder::BE>` | `wire.rs:117` | VAA payload is BE |
| Price message decoded with `from_slice::<byteorder::BigEndian>` | `wire.rs:537` | `PriceFeedMessage` fields are BE |
| `Keccak160 = keccak256(..)[0..20]` (**first** 20 bytes, not last) | `hashers/keccak256_160.rs` | `type Hash = [u8; 20]` |
| leaf = `Keccak160(0x00 ‖ msg)`, node = `Keccak160(0x01 ‖ min(l,r) ‖ max(l,r))` | `accumulators/merkle.rs:25,191,196` | **node pair is SORTED (min,max)** by lexicographic byte compare |
| `MerkleRoot::check`: fold `cur = hash_leaf(item)`; for each proof node `cur = hash_node(cur, node)`; `cur == root` | `accumulators/merkle.rs:79` | sort inside `hash_node` ⇒ **fold direction / sibling order don't matter** |

The `byteorder::LE` occurrences in pythnet-sdk are all generic *serializer*
unit tests, not the production accumulator path — do not be misled by them.

## AccumulatorUpdateData layout (= Hermes `binary.data[0]`, big-endian)

```
offset  field
0..4    magic                 = "PNAU" (0x504e4155)
4       major_version         = 1                     (require == 1)
5       minor_version         = 0                     (require >= 0)
6       trailing: Vec<u8>     → u8 len prefix (currently 0), then that many bytes
7       proof: Proof enum     → u8 variant (0 = WormholeMerkle)      [after trailing]
+2      vaa: PrefixedVec<u16,u8> → u16-BE len, then `vaa_len` bytes
...     updates: Vec<MerklePriceUpdate> → u8 count, then that many updates
```

Each `MerklePriceUpdate`:
```
msg:   PrefixedVec<u16,u8>  → u16-BE len, then `msg_len` bytes   (the PriceFeedMessage)
proof: MerklePath<Keccak160> = Vec<[u8;20]> → u8 count, then count × 20-byte nodes
```
(The existing `extract_vaa_from_accumulator` in `hermes.rs` already parses the
header through the VAA correctly — this just continues past it into `updates[]`.)

## VAA payload = WormholeMessage (big-endian)

The VAA `payload` (everything after `consistency_level`) is:
```
0..4    magic       = "AUWV" (0x41555756)
4       payload: WormholePayload enum → u8 variant (0 = Merkle)
5..13   slot        u64-BE
13..17  ring_size   u32-BE
17..37  root        [u8;20]   ← THE guardian-signed Merkle root (the only trusted anchor)
```
The 20-byte `root` is the sole thing bound by the guardian signatures. It MUST
be read only from here — never from a Hermes-supplied field.

## PriceFeedMessage layout (big-endian, `Message` enum variant 0) — 85 bytes

```
0       disc          u8 = 0 (PriceFeedMessage)
1..33   feed_id       [u8;32]
33..41  price         i64-BE
41..49  conf          u64-BE
49..53  exponent      i32-BE
53..61  publish_time  i64-BE
61..69  prev_publish_time i64-BE
69..77  ema_price     i64-BE      ← the value the oracle uses (matches on-chain reader)
77..85  ema_conf      u64-BE
```
Messages are forward-compatible: parsers must **ignore trailing bytes** beyond
the fields they understand (a future message may append fields). Match on the
leading `disc`; ignore non-`PriceFeedMessage` discriminants.

## Merkle verification (the security-critical core)

```text
k160(x)        = keccak256(x)[0..20]              # FIRST 20 bytes
hash_leaf(m)   = k160( 0x00 ‖ m )
hash_node(a,b) = k160( 0x01 ‖ min(a,b) ‖ max(a,b) )   # sorted (lexicographic)
verify(msg, proof_nodes, root):
    cur = hash_leaf(msg)
    for node in proof_nodes: cur = hash_node(cur, node)
    return cur == root
```
Because `hash_node` sorts its pair, the proof carries no left/right bit and the
fold is order-agnostic — do not add index/direction handling.

## Fixture

`crates/darknyx-tee/tests/fixtures/sol_usd_accumulator.bin` — a real Hermes SOL/USD
`AccumulatorUpdateData` (1311 bytes, guardian set 7, 1 update, proof depth 13).
Recorded ground truth for the cross-check test:
- `ema_price = 7471749900`, `exponent = -8`, `publish_time = 1783978363`
- feed_id `ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d`
- VAA-embedded Merkle root `8ef2f2693c8b116bd14f75a3bbb013dbf95e48ee`, slot `302326856`, ring_size `10000`

(The pre-existing `sol_usd_vaa.bin` is also a full PNAU update, set 7 — kept for
the `hermes.rs` VAA-extraction test.)

## Decision: hand-roll, don't add `pythnet-sdk`

`pythnet-sdk` drags borsh + optional solana-program/anchor deps and a full
serde format we don't need. The VAA verifier is already hand-rolled on
`k256` + `sha3`; the accumulator parse + Keccak160 Merkle verify is ~150 lines
in the same style with a tiny dep surface (`sha3` is already a dependency).
Hand-roll it in `crates/darknyx-tee/src/oracle/accumulator.rs`.
