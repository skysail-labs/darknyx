//! Ed25519Program precompile instruction builder.
//!
//! `tee_forced_settle_batched` verifies the TEE's settle signature
//! by inspecting an Ed25519Program precompile instruction in the
//! same transaction (via the instructions sysvar). This builder
//! produces that precompile ix with the pubkey, signature, and
//! message inlined into the ix data — byte-for-byte matching the
//! SDK's `settle-builder.ts::buildEd25519VerifyIx` and the layout
//! `verify_tee_signature` expects.
//!
//! Header (16 bytes, little-endian), then `pubkey(32) ||
//! signature(64) || message(N)`:
//!
//! ```text
//!   u8  num_signatures   = 1
//!   u8  padding          = 0
//!   u16 signature_offset
//!   u16 signature_ix_index   = 0xFFFF (inlined in this ix)
//!   u16 public_key_offset
//!   u16 public_key_ix_index  = 0xFFFF
//!   u16 message_data_offset
//!   u16 message_data_size
//!   u16 message_ix_index     = 0xFFFF
//! ```

use solana_address::Address;
use solana_instruction::Instruction;

/// Solana Ed25519Program precompile id
/// (`Ed25519SigVerify111111111111111111111111111`). Const so we
/// don't base58-parse per ix.
pub const ED25519_PROGRAM_ID: Address = Address::new_from_array([
    0x03, 0x7d, 0x46, 0xd6, 0x7c, 0x93, 0xfb, 0xbe, 0x12, 0xf9, 0x42, 0x8f, 0x83, 0x8d, 0x40, 0xff,
    0x05, 0x70, 0x74, 0x49, 0x27, 0xf4, 0x8a, 0x64, 0xfc, 0xca, 0x70, 0x44, 0x80, 0x00, 0x00, 0x00,
]);

const HEADER_LEN: usize = 16;
const SENTINEL: u16 = 0xFFFF;

/// Build the Ed25519 precompile verify instruction. `message` is
/// the `canonical_payload_hash` (32 bytes) the TEE signed.
pub fn build_ed25519_verify_ix(
    tee_pubkey: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> Instruction {
    let pk_off = HEADER_LEN;
    let sig_off = pk_off + 32;
    let msg_off = sig_off + 64;

    let mut data = Vec::with_capacity(msg_off + message.len());
    data.push(1u8); // num_signatures
    data.push(0u8); // padding
    data.extend_from_slice(&(sig_off as u16).to_le_bytes());
    data.extend_from_slice(&SENTINEL.to_le_bytes()); // sig ix index
    data.extend_from_slice(&(pk_off as u16).to_le_bytes());
    data.extend_from_slice(&SENTINEL.to_le_bytes()); // pk ix index
    data.extend_from_slice(&(msg_off as u16).to_le_bytes());
    data.extend_from_slice(&(message.len() as u16).to_le_bytes());
    data.extend_from_slice(&SENTINEL.to_le_bytes()); // msg ix index
    debug_assert_eq!(data.len(), HEADER_LEN);

    data.extend_from_slice(tee_pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction {
        program_id: ED25519_PROGRAM_ID,
        accounts: vec![], // precompile takes no accounts
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_id_is_canonical_base58() {
        // The const bytes must base58-encode to the documented
        // Ed25519Program id. If this fails, the const was mistyped.
        assert_eq!(
            ED25519_PROGRAM_ID.to_string(),
            "Ed25519SigVerify111111111111111111111111111"
        );
    }

    #[test]
    fn precompile_data_layout() {
        let pubkey = [0xAA; 32];
        let sig = [0xBB; 64];
        let msg = [0xCC; 32];
        let ix = build_ed25519_verify_ix(&pubkey, &sig, &msg);

        assert_eq!(ix.program_id, ED25519_PROGRAM_ID);
        assert!(ix.accounts.is_empty());

        let d = &ix.data;
        // Total = 16 header + 32 + 64 + 32 = 144.
        assert_eq!(d.len(), 16 + 32 + 64 + 32);

        // Header fields.
        assert_eq!(d[0], 1); // num_signatures
        assert_eq!(d[1], 0); // padding
        let rd = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]);
        assert_eq!(rd(2), 48); // signature_offset = 16 + 32
        assert_eq!(rd(4), 0xFFFF); // sig ix index
        assert_eq!(rd(6), 16); // public_key_offset
        assert_eq!(rd(8), 0xFFFF);
        assert_eq!(rd(10), 112); // message_data_offset = 16 + 32 + 64
        assert_eq!(rd(12), 32); // message_data_size
        assert_eq!(rd(14), 0xFFFF);

        // Inlined data at the declared offsets.
        assert_eq!(&d[16..48], &pubkey);
        assert_eq!(&d[48..112], &sig);
        assert_eq!(&d[112..144], &msg);
    }

    #[test]
    fn message_size_field_tracks_message_len() {
        let ix = build_ed25519_verify_ix(&[0; 32], &[0; 64], &[0u8; 32]);
        let size = u16::from_le_bytes([ix.data[12], ix.data[13]]);
        assert_eq!(size, 32);
    }
}
