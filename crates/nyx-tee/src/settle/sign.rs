//! Ed25519 signing of canonical_payload_hash(payload). The signing
//! key is derived in `crate::keys::ed25519`. The hash construction
//! must equal `vault::canonical_payload_hash` — see CLAUDE.md §6
//! (cross-language byte-equality contract).
