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
//! let (body, body_digest) = MAuthInfo::build_body_with_digest("".to_string());
//! let mut req = Request::new(Method::GET, uri);
//! *req.body_mut() = Some(body);
//! mauth_info.sign_request(&mut req, &body_digest);
//! match client.execute(req).await {
//!     Err(err) => println!("Got error {}", err),
//!     Ok(response) => match mauth_info.validate_response(response).await {
//!         Ok(resp_body) => println!(
//!             "Got validated response with body {}",
//!             &String::from_utf8(resp_body).unwrap()
//!         ),
//!         Err(err) => println!("Error validating response: {:?}", err),
//!     }
//! }
//! # }
//! ```
//!
//! The optional `axum-service` feature provides for a Tower Layer and Service that will
//! authenticate incoming requests via MAuth V2 or V1 and provide to the lower layers a
//! validated app_uuid from the request via the ValidatedRequestDetails struct.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use base64::Engine;
use chrono::prelude::*;
use reqwest::{header::HeaderValue, Client, Method, Request, Url};
use serde::Deserialize;
use thiserror::Error;
use tokio::io;
use uuid::Uuid;

use mauth_core::signer::Signer;

use mauth_core::verifier::Verifier;

const CONFIG_FILE: &str = ".mauth_config.yml";

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

/// This struct holds the app UUID for a validated request. It is meant to be used with the
/// Extension setup in Hyper requests, where it is placed in requests that passed authentication.
/// The custom struct makes it clearer that the request has passed and this is an authenticated
/// app UUID and not some random UUID that some other component put in place for some other
/// purpose.
#[cfg(feature = "axum-service")]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ValidatedRequestDetails {
    pub app_uuid: Uuid,
}

/// All of the configuration data needed to set up a MAuthInfo struct. Implements Deserialize
/// to be read from a YAML file easily, or can be created manually.
#[derive(Deserialize, Clone)]
pub struct ConfigFileSection {
    pub app_uuid: String,
    pub mauth_baseurl: String,
    pub mauth_api_version: String,
    pub private_key_file: String,
    pub v2_only_sign_requests: Option<bool>,
    pub v2_only_authenticate: Option<bool>,
}

impl MAuthInfo {
    /// Construct the MAuthInfo struct based on the contents of the config file `.mauth_config.yml`
    /// present in the current user's home directory. Returns an enum error type that includes the
    /// error types of all crates used.
    pub fn from_default_file() -> Result<MAuthInfo, ConfigReadError> {
        Self::from_config_section(&Self::config_section_from_default_file()?, None)
    }

    fn config_section_from_default_file() -> Result<ConfigFileSection, ConfigReadError> {
        let mut home = dirs::home_dir().unwrap();
        home.push(CONFIG_FILE);
        let config_data = std::fs::read_to_string(&home)?;

        let config_data_value: serde_yaml::Value =
            serde_yaml::from_slice(&config_data.into_bytes())?;
        let common_section = config_data_value
            .get("common")
            .ok_or(ConfigReadError::InvalidFile(None))?;
        let common_section_typed: ConfigFileSection =
            serde_yaml::from_value(common_section.clone())?;
        Ok(common_section_typed)
    }

    /// Construct the MAuthInfo struct based on a passed-in ConfigFileSection instance. The
    /// optional input_keystore is present to support internal cloning and need not be provided
    /// if being used outside of the crate.
    pub fn from_config_section(
        section: &ConfigFileSection,
        input_keystore: Option<Arc<RwLock<HashMap<Uuid, Verifier>>>>,
    ) -> Result<MAuthInfo, ConfigReadError> {
        let full_uri: Url = format!(
            "{}/mauth/{}/security_tokens/",
            &section.mauth_baseurl, &section.mauth_api_version
        )
        .parse()?;

        let pk_data = std::fs::read_to_string(&section.private_key_file)?;

        Ok(MAuthInfo {
            app_id: Uuid::parse_str(&section.app_uuid)?,
            mauth_uri_base: full_uri,
            remote_key_store: input_keystore
                .unwrap_or_else(|| Arc::new(RwLock::new(HashMap::new()))),
            sign_with_v1_also: !section.v2_only_sign_requests.unwrap_or(false),
            allow_v1_auth: !section.v2_only_authenticate.unwrap_or(false),
            signer: Signer::new(section.app_uuid.clone(), pk_data)?,
        })
    }

    /// This method determines how to sign the request automatically while respecting the
    /// `v2_only_sign_requests` flag in the config file. It always signs with the V2 algorithm and
    /// signature, and will also sign with the V1 algorithm, if the configuration permits.
    pub fn sign_request(&self, req: &mut Request, body: &[u8]) -> Result<(), SigningError> {
        self.sign_request_v2(req, body)?;
        if self.sign_with_v1_also {
            self.sign_request_v1(req, body)?;
        }
        Ok(())
    }

    #[cfg(feature = "axum-service")]
    async fn validate_request(
        &self,
        req: axum::extract::Request,
    ) -> Result<axum::extract::Request, MAuthValidationError> {
        let (mut parts, body) = req.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|_| MAuthValidationError::InvalidBody)?;
        match self.validate_request_v2(&parts, &body_bytes).await {
            Ok(host_app_uuid) => {
                parts.extensions.insert(ValidatedRequestDetails {
                    app_uuid: host_app_uuid,
                });
                let new_body = axum::body::Body::from(body_bytes);
                let new_request = axum::extract::Request::from_parts(parts, new_body);
                Ok(new_request)
            }
            Err(err) => {
                if self.allow_v1_auth {
                    match self.validate_request_v1(&parts, &body_bytes).await {
                        Ok(host_app_uuid) => {
                            parts.extensions.insert(ValidatedRequestDetails {
                                app_uuid: host_app_uuid,
                            });
                            let new_body = axum::body::Body::from(body_bytes);
                            let new_request = axum::extract::Request::from_parts(parts, new_body);
                            Ok(new_request)
                        }
                        Err(err) => Err(err),
                    }
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Sign a provided request using the MAuth V2 protocol. The signature consists of 2 headers
    /// containing both a timestamp and a signature string, and will be added to the headers of the
    /// request. It is required to pass a `body_digest` computed by the
    /// [`build_body_with_digest`](#method.build_body_with_digest) method, even if the request is
    /// an empty-body GET.
    ///
    /// Note that, as the request signature includes a timestamp, the request must be sent out
    /// shortly after the signature takes place.
    pub fn sign_request_v2(
        &self,
        req: &mut Request,
        body_data: &[u8],
    ) -> Result<(), SigningError> {
        let timestamp_str = Utc::now().timestamp().to_string();
        let some_string = self.signer.sign_string(
            2,
            req.method().as_str(),
            req.url().path(),
            req.url().query().unwrap_or(""),
            body_data,
            timestamp_str.clone(),
        )?;
        self.set_headers_v2(req, some_string, &timestamp_str);
        Ok(())
    }

    #[cfg(feature = "axum-service")]
    async fn validate_request_v2(
        &self,
        req: &http::request::Parts,
        body_bytes: &bytes::Bytes,
    ) -> Result<Uuid, MAuthValidationError> {
        // let mut hasher = Sha512::default();
        // hasher.update(body_bytes);

        //retrieve and parse auth string
        let sig_header = req
            .headers
            .get("MCC-Authentication")
            .ok_or(MAuthValidationError::NoSig)?
            .to_str()
            .map_err(|_| MAuthValidationError::InvalidSignature)?;
        let (host_app_uuid, raw_signature) = Self::split_auth_string(sig_header, "MWSV2")?;

        //retrieve and validate timestamp
        let ts_str = req
            .headers
            .get("MCC-Time")
            .ok_or(MAuthValidationError::NoTime)?
            .to_str()
            .map_err(|_| MAuthValidationError::InvalidTime)?;
        Self::validate_timestamp(ts_str)?;

        match self.get_app_pub_key(&host_app_uuid).await {
            None => Err(MAuthValidationError::KeyUnavailable),
            Some(verifier) => {
                if let Ok(signature) = String::from_utf8(raw_signature) {
                    match verifier.verify_signature(
                        2,
                        req.method.as_str(),
                        req.uri.path(),
                        req.uri.query().unwrap_or(""),
                        body_bytes,
                        ts_str,
                        signature,
                    ) {
                        Ok(()) => Ok(host_app_uuid),
                        Err(_) => Err(MAuthValidationError::SignatureVerifyFailure),
                    }
                } else {
                    Err(MAuthValidationError::SignatureVerifyFailure)
                }
            }
        }
    }

    #[cfg(feature = "axum-service")]
    async fn validate_request_v1(
        &self,
        req: &http::request::Parts,
        body_bytes: &bytes::Bytes,
    ) -> Result<Uuid, MAuthValidationError> {
        //retrieve and parse auth string
        let sig_header = req
            .headers
            .get("X-MWS-Authentication")
            .ok_or(MAuthValidationError::NoSig)?
            .to_str()
            .map_err(|_| MAuthValidationError::InvalidSignature)?;
        let (host_app_uuid, raw_signature) = Self::split_auth_string(sig_header, "MWS")?;

        //retrieve and validate timestamp
        let ts_str = req
            .headers
            .get("X-MWS-Time")
            .ok_or(MAuthValidationError::NoTime)?
            .to_str()
            .map_err(|_| MAuthValidationError::InvalidTime)?;
        Self::validate_timestamp(ts_str)?;

        match self.get_app_pub_key(&host_app_uuid).await {
            None => Err(MAuthValidationError::KeyUnavailable),
            Some(verifier) => {
                if let Ok(signature) = String::from_utf8(raw_signature) {
                    match verifier.verify_signature(
                        1,
                        req.method.as_str(),
                        req.uri.path(),
                        req.uri.query().unwrap_or(""),
                        body_bytes,
                        ts_str,
                        signature,
                    ) {
                        Ok(()) => Ok(host_app_uuid),
                        Err(_) => Err(MAuthValidationError::SignatureVerifyFailure),
                    }
                } else {
                    Err(MAuthValidationError::SignatureVerifyFailure)
                }
            }
        }
    }

    fn set_headers_v2(&self, req: &mut Request, signature: String, timestamp_str: &str) {
        let sig_head_str = format!("MWSV2 {}:{};", self.app_id, &signature);
        let headers = req.headers_mut();
        headers.insert("MCC-Time", HeaderValue::from_str(timestamp_str).unwrap());
        headers.insert(
            "MCC-Authentication",
            HeaderValue::from_str(&sig_head_str).unwrap(),
        );
    }

    /// Sign a provided request using the MAuth V1 protocol. The signature consists of 2 headers
    /// containing both a timestamp and a signature string, and will be added to the headers of the
    /// request. It is required to pass a `body`, even if the request is an empty-body GET.
    ///
    /// Note that, as the request signature includes a timestamp, the request must be sent out
    /// shortly after the signature takes place.
    pub fn sign_request_v1(
        &self,
        req: &mut Request,
        body_data: &[u8],
    ) -> Result<(), SigningError> {
        let timestamp_str = Utc::now().timestamp().to_string();

        let sig = self.signer.sign_string(
            1,
            req.method().as_str(),
            req.url().path(),
            req.url().query().unwrap_or(""),
            body_data,
            timestamp_str.clone(),
        )?;

        let headers = req.headers_mut();
        headers.insert("X-MWS-Time", HeaderValue::from_str(&timestamp_str).unwrap());
        headers.insert("X-MWS-Authentication", HeaderValue::from_str(&sig).unwrap());
        Ok(())
    }

    fn validate_timestamp(timestamp_str: &str) -> Result<(), MAuthValidationError> {
        let ts_num: i64 = timestamp_str
            .parse()
            .map_err(|_| MAuthValidationError::InvalidTime)?;
        let ts_diff = ts_num - Utc::now().timestamp();
        if !(-300..=300).contains(&ts_diff) {
            Err(MAuthValidationError::InvalidTime)
        } else {
            Ok(())
        }
    }

    fn split_auth_string(
        auth_str: &str,
        expected_prefix: &str,
    ) -> Result<(Uuid, Vec<u8>), MAuthValidationError> {
        let header_pattern = vec![' ', ':', ';'];
        let mut header_split = auth_str.split(header_pattern.as_slice());

        let start_str = header_split
            .next()
            .ok_or(MAuthValidationError::InvalidSignature)?;
        if start_str != expected_prefix {
            return Err(MAuthValidationError::InvalidSignature);
        }
        let host_uuid_str = header_split
            .next()
            .ok_or(MAuthValidationError::InvalidSignature)?;
        let host_app_uuid =
            Uuid::parse_str(host_uuid_str).map_err(|_| MAuthValidationError::InvalidSignature)?;
        let signature_encoded_string = header_split
            .next()
            .ok_or(MAuthValidationError::InvalidSignature)?;
        let b64 = base64::engine::general_purpose::STANDARD;
        let raw_signature: Vec<u8> = b64
            .decode(signature_encoded_string)
            .map_err(|_| MAuthValidationError::InvalidSignature)?;
        Ok((host_app_uuid, raw_signature))
    }

    async fn get_app_pub_key(&self, app_uuid: &Uuid) -> Option<Verifier> {
        {
            let key_store = self.remote_key_store.read().unwrap();
            if let Some(pub_key) = key_store.get(app_uuid) {
                return Some(pub_key.clone());
            }
        }
        let client = Client::new();
        let uri = self.mauth_uri_base.join(&format!("{}", &app_uuid)).unwrap();
        let mut req = Request::new(Method::GET, uri);
        // This can only error with invalid UTF8 format, which is impossible here
        self.sign_request_v2(&mut req, &[]).unwrap();
        let mauth_response = client.execute(req).await;
        match mauth_response {
            Err(_) => None,
            Ok(response) => {
                if let Ok(response_obj) = response.json::<serde_json::Value>().await {
                    if let Some(pub_key_str) = response_obj
                        .pointer("/security_token/public_key_str")
                        .and_then(|s| s.as_str())
                        .map(|st| st.to_owned())
                    {
                        if let Ok(verifier) = Verifier::new(*app_uuid, pub_key_str) {
                            let mut key_store = self.remote_key_store.write().unwrap();
                            key_store.insert(*app_uuid, verifier.clone());
                            Some(verifier)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod config_test;
#[cfg(test)]
mod protocol_test_suite;

/// All of the possible errors that can take place when attempting to read a config file. Errors
/// are specific to the libraries that created them, and include the details from those libraries.
#[derive(Debug, Error)]
pub enum ConfigReadError {
    #[error("File Read Error: {0}")]
    FileReadError(#[from] io::Error),
    #[error("Not a valid maudit config file: {0:?}")]
    InvalidFile(Option<serde_yaml::Error>),
    #[error("MAudit URI not valid: {0}")]
    InvalidUri(#[from] url::ParseError),
    #[error("App UUID not valid: {0}")]
    InvalidAppUuid(#[from] uuid::Error),
    #[error("Unable to parse RSA private key: {0}")]
    PrivateKeyDecodeError(String),
}

impl From<mauth_core::error::Error> for ConfigReadError {
    fn from(err: mauth_core::error::Error) -> ConfigReadError {
        match err {
            mauth_core::error::Error::PrivateKeyDecodeError(pkey_err) => {
                ConfigReadError::PrivateKeyDecodeError(format!("{}", pkey_err))
            }
            _ => panic!("should not be possible to get this error type from signer construction"),
        }
    }
}

impl From<serde_yaml::Error> for ConfigReadError {
    fn from(err: serde_yaml::Error) -> ConfigReadError {
        ConfigReadError::InvalidFile(Some(err))
    }
}

/// All of the possible errors that can take place when attempting to verify a response signature
#[derive(Debug, Error)]
pub enum MAuthValidationError {
    /// The timestamp of the response was either invalid or outside of the permitted
    /// range
    #[error("The timestamp of the response was either invalid or outside of the permitted range")]
    InvalidTime,
    /// The MAuth signature of the response was either missing or incorrectly formatted
    #[error("The MAuth signature of the response was either missing or incorrectly formatted")]
    InvalidSignature,
    /// The timestamp header of the response was missing
    #[error("The timestamp header of the response was missing")]
    NoTime,
    /// The signature header of the response was missing
    #[error("The signature header of the response was missing")]
    NoSig,
    /// An error occurred while attempting to retrieve part of the response body
    #[error("An error occurred while attempting to retrieve part of the response body")]
    ResponseProblem,
    /// The response body failed to parse
    #[error("The response body failed to parse")]
    InvalidBody,
    /// Attempt to retrieve a key to verify the response failed
    #[error("Attempt to retrieve a key to verify the response failed")]
    KeyUnavailable,
    /// The body of the response did not match the signature
    #[error("The body of the response did not match the signature")]
    SignatureVerifyFailure,
}

/// All of the errors that can take place while attempting to sign a request
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Unable to handle the URL as the format was invalid: {0}")]
    UrlEncodingError(std::string::FromUtf8Error),
}

impl From<mauth_core::error::Error> for SigningError {
    fn from(err: mauth_core::error::Error) -> SigningError {
        match err {
            mauth_core::error::Error::UrlEncodingError(url_err) => {
                SigningError::UrlEncodingError(url_err)
            }
            _ => panic!("should not be possible to get this error type from signing a request"),
        }
    }
}

#[cfg(feature = "axum-service")]
pub mod axum_service;
