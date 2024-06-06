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
//! # use mauth_client::MAuthInfo;
//! # use reqwest::{Client, Request, Body, Url, Method, header::HeaderValue, Response};
//! # async fn make_signed_request() {
//! let mauth_info = MAuthInfo::from_default_file().unwrap();
//! let client = Client::new();
//! let uri: Url = "https://www.example.com/".parse().unwrap();
//! let mut req = Request::new(Method::GET, uri);
//! mauth_info.sign_request(&mut req, &[]);
//! match client.execute(req).await {
//!     Err(err) => println!("Got error {}", err),
//!     Ok(response) => println!("Got validated response with body {}", response.text().await.unwrap()),
//! }
//! # }
//! ```
//!
//! The optional `axum-service` feature provides for a Tower Layer and Service that will
//! authenticate incoming requests via MAuth V2 or V1 and provide to the lower layers a
//! validated app_uuid from the request via the ValidatedRequestDetails struct.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use reqwest::Url;
use uuid::Uuid;
use mauth_core::{signer::Signer, verifier::Verifier};

/// This is the primary struct of this class. It contains all of the information
/// required to sign requests using the MAuth protocol and verify the responses.
///
/// Note that it contains a cache of response keys for verifying response signatures. This cache
/// makes the struct non-Sync.
pub struct MAuthInfo {
    app_id: Uuid,
    remote_key_store: Arc<RwLock<HashMap<Uuid, Verifier>>>,
    mauth_uri_base: Url,
    sign_with_v1_also: bool,
    allow_v1_auth: bool,
    signer: Signer,
}

#[cfg(test)]
mod protocol_test_suite;
/// Tower Service and Layer to allow Tower-integrated servers to validate incoming request
#[cfg(feature = "axum-service")]
pub mod axum_service;
/// Implementation of code to validate incoming requests
#[cfg(feature = "axum-service")]
pub mod validate_incoming;
/// Implementation of code to sign outgoing requests
pub mod sign_outgoing;
/// Helpers to parse configuration files or supply structs and construct instances of the main struct
pub mod config;
