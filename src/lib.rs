#![forbid(unsafe_code)]
//! # mauth-client
//!
//! This crate allows users of the Reqwest crate for making HTTP requests to sign those requests with
//! the MAuth protocol, and verify the responses. Usage example:
//!
//! **Note**: This crate and Rust support within Medidata is considered experimental. Do not
//! release any code to Production or deploy in a Client-accessible environment without getting
//! approval for the full stack used through the Architecture and Security groups.
//!
//! ```no_run
//! use mauth_client::MAuthInfo;
//! use reqwest::Client;
//! # async fn make_signed_request() {
//! let mauth_info = MAuthInfo::from_default_file().unwrap();
//! let client = Client::new();
//! let mut req = client.get("https://www.example.com/").build().unwrap();
//! mauth_info.sign_request(&mut req);
//! match client.execute(req).await {
//!     Err(err) => println!("Got error {}", err),
//!     Ok(response) => println!("Got validated response with body {}", response.text().await.unwrap()),
//! }
//! # }
//! ```
//!
//!
//! The above code will read your mauth configuration from a file in `~/.mauth_config.yml` which format is:
//! ```yaml
//! common: &common
//!   mauth_baseurl: https://<URL of MAUTH SERVER>
//!   mauth_api_version: v1
//!   app_uuid: <YOUR APP UUID HERE>
//!   private_key_file: <PATH TO MAUTH KEY>
//! ```
//!
//! The optional `axum-service` feature provides for a Tower Layer and Service that will
//! authenticate incoming requests via MAuth V2 or V1 and provide to the lower layers a
//! validated app_uuid from the request via the ValidatedRequestDetails struct.

use mauth_core::signer::Signer;
use mauth_core::verifier::Verifier;
use reqwest::Url;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// This is the primary struct of this class. It contains all of the information
/// required to sign requests using the MAuth protocol and verify the responses.
///
/// Note that it contains a cache of response keys for verifying response signatures. This cache
/// makes the struct non-Sync.
#[allow(dead_code)]
pub struct MAuthInfo {
    app_id: Uuid,
    sign_with_v1_also: bool,
    signer: Signer,
    remote_key_store: Arc<RwLock<HashMap<Uuid, Verifier>>>,
    mauth_uri_base: Url,
    allow_v1_auth: bool,
}

/// Tower Service and Layer to allow Tower-integrated servers to validate incoming request
#[cfg(feature = "axum-service")]
pub mod axum_service;
/// Helpers to parse configuration files or supply structs and construct instances of the main struct
pub mod config;
#[cfg(test)]
mod protocol_test_suite;
/// Implementation of code to sign outgoing requests
pub mod sign_outgoing;
/// Implementation of code to validate incoming requests
#[cfg(feature = "axum-service")]
pub mod validate_incoming;
