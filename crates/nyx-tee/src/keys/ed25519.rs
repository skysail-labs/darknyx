//! Ed25519 signer derivation from a dstack-supplied seed.
//!
//! Path: `"nyx/ed25519-signer/v1"`. **Do not change this string
//! without bumping the compose-hash and running the multisig
//! rotation ceremony** — see `docs/tee-attestation-flow.md` §5.

// Phase-1 stub. The real signature is roughly:
//
//   pub async fn derive(client: &DstackClient) -> anyhow::Result<SigningKey> {
//       let resp = client.get_key(Some("nyx/ed25519-signer/v1".into()), None).await?;
//       let seed: [u8; 32] = resp.decode_key().try_into()?;
//       Ok(SigningKey::from_bytes(&seed))
//   }
