//! `GET /account` — **deferred by design** (Phase 2c decision).
//!
//! The openapi `Account` shape wants per-account `balances` +
//! `outstanding_notes`, but the TEE *cannot* compute those: linking an
//! `account_id` to a user's notes requires the spending key, which the
//! TEE never sees — that unlinkability is a core dark-pool property
//! (`docs/tee-architecture.md` §11.3). The trustless design is that
//! **clients derive their own balances + spendable notes** from the
//! `/tree/*` endpoints (inclusion proofs against the current root) plus
//! their own keys; the TEE is never in a position to deanonymise a
//! user.
//!
//! So this returns `501 Not Implemented` with a pointer rather than
//! fabricating data the TEE doesn't legitimately have. If we ever add
//! an opt-in client-side view model it'll land here.

use axum::http::StatusCode;

/// `GET /account` — bearer-protected, but always `501`. See module doc.
pub async fn get_account() -> (StatusCode, String) {
    (
        StatusCode::NOT_IMPLEMENTED,
        "per-account balances/notes are computed client-side from /tree/* + your keys; \
         the TEE never sees a spending key (see docs/tee-architecture.md §11.3)"
            .to_string(),
    )
}
