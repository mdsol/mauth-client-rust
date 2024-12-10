#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use ::reqwest_middleware::ClientWithMiddleware;
use mauth_core::signer::Signer;
use mauth_core::verifier::Verifier;
use reqwest::Url;
use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock, RwLock};
use uuid::Uuid;

/// This is the primary struct of this class. It contains all of the information
/// required to sign requests using the MAuth protocol and verify the responses.
///
/// Note that it contains a cache of response keys for verifying response signatures. This cache
/// makes the struct non-Sync.
#[derive(Clone)]
pub struct MAuthInfo {
    app_id: Uuid,
    sign_with_v1_also: bool,
    signer: Signer,
    mauth_uri_base: Url,
    allow_v1_auth: bool,
}

static CLIENT: OnceLock<ClientWithMiddleware> = OnceLock::new();

static PUBKEY_CACHE: LazyLock<RwLock<HashMap<Uuid, Verifier>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

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
