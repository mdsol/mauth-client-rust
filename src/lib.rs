#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use ::reqwest_middleware::ClientWithMiddleware;
use mauth_core::signer::Signer;
use reqwest::Url;
use std::sync::OnceLock;
use uuid::Uuid;

#[cfg(feature = "axum-service")]
use crate::validate_incoming::{DEFAULT_PUBKEY_CACHE_CAPACITY, PubkeyCache};

/// This is the primary struct of this class. It contains all of the information
/// required to sign requests using the MAuth protocol and verify the responses.
///
/// The cache of keys used to verify incoming signatures is process-wide rather than held
/// here, so this struct stays cheap to clone -- which matters, because the validation
/// services clone it for every request they handle.
#[derive(Clone)]
pub struct MAuthInfo {
    app_id: Uuid,
    sign_with_v1_also: bool,
    signer: Signer,
    // These two are only consulted when validating incoming requests, which the
    // `axum-service` feature gates. They are always populated regardless, so the
    // struct shape does not vary between feature sets.
    #[cfg_attr(not(feature = "axum-service"), allow(dead_code))]
    mauth_uri_base: Url,
    #[cfg_attr(not(feature = "axum-service"), allow(dead_code))]
    allow_v1_auth: bool,
}

static CLIENT: OnceLock<ClientWithMiddleware> = OnceLock::new();

#[cfg(feature = "axum-service")]
static PUBKEY_CACHE: OnceLock<PubkeyCache> = OnceLock::new();

/// The process-wide cache of verifier keys fetched from MAuth.
///
/// Deliberately global rather than a field on [`MAuthInfo`]:
/// `RequiredMAuthValidationService::call` clones its `MAuthInfo` for *every*
/// request, and that `Clone` impl rebuilds the struct from config, so a
/// per-instance cache would never survive to see a second lookup.
///
/// Falls back to [`DEFAULT_PUBKEY_CACHE_CAPACITY`] if a lookup somehow happens
/// before any config has been loaded.
#[cfg(feature = "axum-service")]
pub(crate) fn pubkey_cache() -> &'static PubkeyCache {
    PUBKEY_CACHE.get_or_init(|| PubkeyCache::new(DEFAULT_PUBKEY_CACHE_CAPACITY))
}

/// Size the key cache from configuration.
///
/// First caller wins, matching the behavior of `CLIENT`: a later
/// `ConfigFileSection` naming a different capacity is silently ignored.
#[cfg(feature = "axum-service")]
pub(crate) fn init_pubkey_cache(capacity: Option<usize>) {
    PUBKEY_CACHE
        .get_or_init(|| PubkeyCache::new(capacity.unwrap_or(DEFAULT_PUBKEY_CACHE_CAPACITY)));
}

/// Tower Service and Layer to allow Tower-integrated servers to validate incoming request
#[cfg(feature = "axum-service")]
pub mod axum_service;
/// Helpers to parse configuration files or supply structs and construct instances of the main struct
pub mod config;
#[cfg(test)]
mod protocol_test_suite;
mod reqwest_middleware;
/// Implementation of code to sign outgoing requests
pub mod sign_outgoing;
/// Implementation of code to validate incoming requests
#[cfg(feature = "axum-service")]
pub mod validate_incoming;
