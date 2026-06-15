//! Account-scoped reads + settings.
//!
//! `GET /account` returns the caller's **open orders** — the one slice of
//! account state the TEE legitimately holds (it tracks the order_id→account map
//! at intake). It deliberately does NOT return balances or notes: linking an
//! account to its notes needs the spending key, which the TEE never sees — that
//! unlinkability is a core dark-pool property (`docs/tee-architecture.md`
//! §11.3). Clients derive balances + spendable notes themselves from `/tree/*`
//! + their own keys.
//!
//! `GET`/`PUT /account/settings` read + update per-account preferences
//! (currently the cancel-on-disconnect default), persisted in `accounts.db`.

use std::sync::Arc;

use axum::{extract::State, Extension, Json};
use darkpool_matcher::book::{OrderSide, OrderStatus, OrderType};
use serde::Serialize;

use super::auth::{AccountSettings, Authorized};
use super::error::ApiError;
use super::state::ApiState;

/// One of the caller's open orders. Same shape as `GET /orders/{id}`.
#[derive(Debug, Serialize)]
pub struct OpenOrder {
    pub order_id: String,
    pub side: &'static str,
    pub order_type: &'static str,
    pub status: &'static str,
    pub amount: u64,
    pub filled_quantity: u64,
    pub price_limit: u64,
    pub expiry_slot: u64,
    pub arrival_slot: u64,
}

/// `GET /account` response: the caller's open orders (balances are client-side).
#[derive(Debug, Serialize)]
pub struct AccountSnapshot {
    pub account_id: String,
    pub open_orders: Vec<OpenOrder>,
}

/// `GET /account` — bearer. Returns the orders this account placed that are
/// still in the book. Balances/notes are intentionally absent (the TEE has no
/// spending key — see the module doc).
pub async fn get_account(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
) -> Result<Json<AccountSnapshot>, ApiError> {
    // The order ids this account owns (intake-time order_id→account map).
    let order_ids: Vec<String> = {
        let owners = state.order_owner.read().await;
        owners
            .iter()
            .filter(|(_, acct)| *acct == &auth.account_id)
            .map(|(oid, _)| oid.clone())
            .collect()
    };

    let mut open_orders = Vec::new();
    if let Some(matcher) = state.matcher.as_ref() {
        let st = matcher.read().await;
        for oid_hex in order_ids {
            let Ok(bytes) = hex::decode(&oid_hex) else {
                continue;
            };
            let Ok(oid): Result<[u8; 16], _> = bytes.as_slice().try_into() else {
                continue;
            };
            // Only orders still in the book (a terminal order's owner mapping is
            // dropped, but guard anyway).
            if let Some(o) = st.book().get(&oid) {
                open_orders.push(OpenOrder {
                    order_id: oid_hex,
                    side: match o.side {
                        OrderSide::Bid => "bid",
                        OrderSide::Ask => "ask",
                    },
                    order_type: match o.order_type {
                        OrderType::Limit => "limit",
                        OrderType::Ioc => "ioc",
                        OrderType::Fok => "fok",
                    },
                    status: match o.status {
                        OrderStatus::Empty => "empty",
                        OrderStatus::Pending => "pending",
                        OrderStatus::Matched => "matched",
                        OrderStatus::Expired => "expired",
                        OrderStatus::Cancelled => "cancelled",
                    },
                    amount: o.amount,
                    filled_quantity: o.filled_quantity,
                    price_limit: o.price_limit,
                    expiry_slot: o.expiry_slot,
                    arrival_slot: o.arrival_slot,
                });
            }
        }
    }

    Ok(Json(AccountSnapshot {
        account_id: auth.account_id,
        open_orders,
    }))
}

/// `GET /account/settings` — bearer. The caller's current preferences.
pub async fn get_settings(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
) -> Result<Json<AccountSettings>, ApiError> {
    let reg = state.accounts.read().await;
    let creds = reg
        .lookup(&auth.account_id)
        .ok_or_else(|| ApiError::not_found("account not found"))?;
    Ok(Json(creds.settings.clone()))
}

/// `PUT /account/settings` — bearer. Replace the caller's preferences, then
/// persist. The body is a full [`AccountSettings`] (omitted fields default).
pub async fn put_settings(
    State(state): State<Arc<ApiState>>,
    Extension(auth): Extension<Authorized>,
    Json(new_settings): Json<AccountSettings>,
) -> Result<Json<AccountSettings>, ApiError> {
    {
        let mut reg = state.accounts.write().await;
        if !reg.set_settings(&auth.account_id, new_settings.clone()) {
            return Err(ApiError::not_found("account not found"));
        }
    }
    // Best-effort persist so the setting survives a restart (same path as
    // register/revoke).
    state.persist_auth().await;
    Ok(Json(new_settings))
}
