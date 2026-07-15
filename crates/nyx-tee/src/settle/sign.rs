//! TEE signing of `canonical_payload_hash(payload)`.
//!
//! The TEE's Ed25519 key (derived in `crate::keys::ed25519`, same
//! key as the `tee_authority` Signer + the Solana fee-payer) signs
//! the 32-byte canonical payload hash. The resulting 64-byte
//! signature is inlined into the Ed25519 precompile ix
//! ([`super::ed25519::build_ed25519_verify_ix`]); the on-chain
//! `verify_tee_signature` re-derives the hash, finds the precompile
//! ix in the instructions sysvar, and asserts the (pubkey, message,
//! signature) triple matches.
//!
//! The hash construction MUST equal `vault::canonical_payload_hash`
//! — that contract is owned + tested by
//! [`super::payload::MatchResultPayload::canonical_hash`] (the
//! fixed-vector parity test).

use ed25519_dalek::{Signer as _, SigningKey};

use super::payload::MatchResultPayload;

/// Sign a settle payload's canonical hash. Returns the 32-byte
/// message (the hash itself) + the 64-byte detached signature,
/// ready to hand to the Ed25519 precompile builder.
///
/// `signing_key` is `DerivedSigner::key` — the same Ed25519 key
/// registered as `vault_config.tee_pubkey`.
pub fn sign_payload(
    signing_key: &SigningKey,
    payload: &MatchResultPayload,
) -> ([u8; 32], [u8; 64]) {
    let hash = payload.canonical_hash();
    let sig = signing_key.sign(&hash);
    (hash, sig.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    fn dummy_payload() -> MatchResultPayload {
        MatchResultPayload {
            match_id: [0x11; 16],
            note_a_commitment: [0xA1; 32],
            note_b_commitment: [0xB1; 32],
            note_c_commitment: [0xC1; 32],
            note_d_commitment: [0xD1; 32],
            note_e_commitment: [0; 32],
            note_f_commitment: [0; 32],
            order_id_a: [0x01; 16],
            order_id_b: [0x02; 16],
            note_fee_base_commitment: [0; 32],
            note_fee_quote_commitment: [0; 32],
            buyer_relock_order_id: [0; 16],
            buyer_relock_expiry: 0,
            seller_relock_order_id: [0; 16],
            seller_relock_expiry: 0,
            batch_slot: 0,
            fill_recovery: [0u8; 128],
        }
    }

    #[test]
    fn signature_verifies_against_pubkey() {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let payload = dummy_payload();
        let (msg, sig_bytes) = sign_payload(&key, &payload);

        // The message is the canonical hash.
        assert_eq!(msg, payload.canonical_hash());

        // The signature verifies under the signer's pubkey — this
        // is exactly what the on-chain precompile checks.
        let vk: VerifyingKey = key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    #[test]
    fn different_payloads_yield_different_messages() {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let mut p2 = dummy_payload();
        p2.match_id = [0x99; 16];
        let (m1, _) = sign_payload(&key, &dummy_payload());
        let (m2, _) = sign_payload(&key, &p2);
        assert_ne!(m1, m2);
    }
}
