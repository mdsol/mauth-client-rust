//! # mauth-client
//!
//! This crate allows users of the Hyper crate for making HTTP requests to sign those requests with
//! the MAuth protocol, and verify the responses. Usage example:
//!
//! ```no_run
//! # use mauth_client::MAuthInfo;
//! # use hyper::{Body, Client, Method, Request, Response};
//! # use hyper_tls::HttpsConnector;
//! # async fn make_signed_request() {
//! let mauth_info = MAuthInfo::from_default_file().unwrap();
//! let https = HttpsConnector::new();
//! let client = Client::builder().build::<_, hyper::Body>(https);
//! let uri: hyper::Uri = "https://www.example.com/".parse().unwrap();
//! let (body, body_digest) = MAuthInfo::build_body_with_digest("".to_string());
//! let mut req = Request::new(body);
//! *req.method_mut() = Method::GET;
//! *req.uri_mut() = uri.clone();
//! mauth_info.sign_request(&mut req, &body_digest);
//! match client.request(req).await {
//!     Err(err) => println!("Got error {}", err),
//!     Ok(response) => match mauth_info.validate_response(response).await {
//!         Ok(resp_body) => println!("Got validated response body {}", &resp_body),
//!         Err(err) => println!("Error validating response: {:?}", err),
//!     }
//! }
//! # }
//! ```

use std::cell::RefCell;
use std::collections::HashMap;

use chrono::prelude::*;
use hyper::body::HttpBody;
use hyper::header::HeaderValue;
use hyper::{Body, Client, Method, Request, Response};
use hyper_tls::HttpsConnector;
use percent_encoding::{percent_decode_str, percent_encode, AsciiSet, NON_ALPHANUMERIC};
use regex::{Captures, Regex};
use ring::rand::SystemRandom;
use ring::signature::{
    RsaKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_SHA512,
};
use serde::Deserialize;
use sha2::{Digest, Sha512};
use tokio::io;
use uuid::Uuid;

use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};

const CONFIG_FILE: &str = ".mauth_config.yml";

/// This is the primary struct of this class. It contains all of the information
/// required to sign requests using the MAuth protocol and verify the responses.
///
/// Note that it contains a cache of response keys for verifying response signatures. This cache
/// makes the struct non-Sync.
pub struct MAuthInfo {
    app_id: Uuid,
    private_key: RsaKeyPair,
    openssl_private_key: Rsa<Private>,
    mauth_uri_base: hyper::Uri,
    remote_key_store: RefCell<HashMap<Uuid, Rsa<Public>>>,
    sign_with_v1_also: bool,
    allow_v1_response_auth: bool,
}

/// This struct holds the digest information required to perform the signing operation. It is a
/// custom struct to enforce the requirement that the
/// [`build_body_with_digest`](#method.build_body_with_digest) function's output be passed to the
/// signing methods.
pub struct BodyDigest {
    digest_str: String,
    body_data: Vec<u8>,
}

#[derive(Deserialize)]
struct ConfigFileSection {
    app_uuid: String,
    mauth_baseurl: String,
    mauth_api_version: String,
    private_key_file: String,
    v2_only_sign_requests: Option<bool>,
    v2_only_authenticate: Option<bool>,
}

impl MAuthInfo {
    /// Construct the MAuthInfo struct based on the contents of the config file `.mauth_config.yml`
    /// present in the current user's home directory. Returns an enum error type that includes the
    /// error types of all crates used.
    pub fn from_default_file() -> Result<MAuthInfo, ConfigReadError> {
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
        Self::from_config_section(common_section_typed)
    }

    fn from_config_section(section: ConfigFileSection) -> Result<MAuthInfo, ConfigReadError> {
        let full_uri: hyper::Uri = format!(
            "{}/mauth/{}/security_tokens/",
            &section.mauth_baseurl, &section.mauth_api_version
        )
        .parse()?;

        let pk_data = std::fs::read_to_string(&section.private_key_file)?;
        let openssl_key = PKey::private_key_from_pem(&pk_data.into_bytes())?;
        let der_key_data = openssl_key.private_key_to_der()?;

        Ok(MAuthInfo {
            app_id: Uuid::parse_str(&section.app_uuid)?,
            mauth_uri_base: full_uri,
            remote_key_store: RefCell::new(HashMap::new()),
            private_key: RsaKeyPair::from_der(&der_key_data)?,
            openssl_private_key: openssl_key.rsa()?,
            sign_with_v1_also: !section.v2_only_sign_requests.unwrap_or(false),
            allow_v1_response_auth: !section.v2_only_authenticate.unwrap_or(false),
        })
    }

    /// The MAuth Protocol requires computing a digest of the full text body of the request to be
    /// sent. This is incompatible with the Hyper crate's structs, which do not allow the body of a
    /// constructed Request to be read. To solve this, use this function to compute both the body to
    /// be used to build the Request struct, and the digest struct to be passed to the
    /// [`sign_request_v2`](#method.sign_request_v2) function.
    ///
    /// Note that this method must be used with all empty-body requests, including GET requests.
    pub fn build_body_with_digest(body: String) -> (Body, BodyDigest) {
        let mut hasher = Sha512::default();
        hasher.update(body.as_bytes());
        (
            Body::from(body.clone()),
            BodyDigest {
                digest_str: hex::encode(hasher.finalize()),
                body_data: body.into_bytes(),
            },
        )
    }

    /// The MAuth Protocol requires computing a digest of the full text body of the request to be
    /// sent. This is incompatible with the Hyper crate's structs, which do not allow the body of a
    /// constructed Request to be read. To solve this, use this function to compute both the body to
    /// be used to build the Request struct, and the digest struct to be passed to the
    /// [`sign_request_v2`](#method.sign_request_v2) function.
    ///
    /// This function is an alternate version of the build_body_with_digest function that allows
    /// the user to build request bodies from data that does not meet the Rust String type
    /// requirements of being valid UTF8. Any binary data can be transformed into the appropriate
    /// objects and signed using this function.
    ///
    /// Note that this method must be used with all empty-body requests, including GET requests.
    pub fn build_body_with_digest_from_bytes(body: Vec<u8>) -> (Body, BodyDigest) {
        let mut hasher = Sha512::default();
        hasher.update(body.clone());
        (
            Body::from(body.clone()),
            BodyDigest {
                digest_str: hex::encode(hasher.finalize()),
                body_data: body,
            },
        )
    }

    /// This method determines how to sign the request automatically while respecting the
    /// `v2_only_sign_requests` flag in the config file. It always signs with the V2 algorithm and
    /// signature, and will also sign with the V1 algorithm, if the configuration permits.
    pub fn sign_request(&self, mut req: &mut Request<Body>, body_digest: &BodyDigest) {
        self.sign_request_v2(&mut req, &body_digest);
        if self.sign_with_v1_also {
            self.sign_request_v1(&mut req, &body_digest);
        }
    }

    /// Validate that a Hyper Response contains a valid MAuth signature. Returns either the
    /// validated response body, or an error with details on why the signature was invalid.
    ///
    /// This method will attempt to validate a V2 signature first. If that fails, and if the
    /// flag `allow_v1_response_auth` is set in the configuration, it will then attempt to validate
    /// a V1 signature. It will return `Ok(body)` if the request successfully authenticates,
    /// otherwise, it will return the most recent validation error.
    ///
    /// This method is `async` because it may make a HTTP request to the MAuth server in order to
    /// retrieve the public key for the application that signed the response. Application keys are
    /// cached in the MAuth struct, so the request only needs to be made once.
    pub async fn validate_response(
        &self,
        response: Response<Body>,
    ) -> Result<String, MAuthValidationError> {
        let (parts, body) = response.into_parts();
        let body_raw: Vec<u8> = Self::bytes_from_body(body).await?;
        match self.validate_response_v2(&parts, &body_raw).await {
            Ok(body) => Ok(body),
            Err(v2_error) => {
                if self.allow_v1_response_auth {
                    self.validate_response_v1(&parts, &body_raw).await
                } else {
                    Err(v2_error)
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
    pub fn sign_request_v2(&self, mut req: &mut Request<Body>, body_digest: &BodyDigest) {
        let timestamp_str = Utc::now().timestamp().to_string();
        let string_to_sign = self.get_signing_string_v2(&req, &body_digest, &timestamp_str);
        let signature = self.sign_string_v2(string_to_sign);
        self.set_headers_v2(&mut req, signature, &timestamp_str);
    }

    fn get_signing_string_v2(
        &self,
        req: &Request<Body>,
        body_digest: &BodyDigest,
        timestamp_str: &str,
    ) -> String {
        let encoded_query: String = req
            .uri()
            .query()
            .map_or("".to_string(), |q| Self::encode_query(q));
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            req.method(),
            Self::normalize_url(req.uri().path()),
            &body_digest.digest_str,
            &self.app_id,
            &timestamp_str,
            &encoded_query
        )
    }

    fn sign_string_v2(&self, string: String) -> String {
        let mut signature = vec![0; self.private_key.public_modulus_len()];
        self.private_key
            .sign(
                &RSA_PKCS1_SHA512,
                &SystemRandom::new(),
                &string.into_bytes(),
                &mut signature,
            )
            .unwrap();
        base64::encode(&signature)
    }

    fn set_headers_v2(&self, req: &mut Request<Body>, signature: String, timestamp_str: &str) {
        let sig_head_str = format!("MWSV2 {}:{};", self.app_id, &signature);
        let headers = req.headers_mut();
        headers.insert("MCC-Time", HeaderValue::from_str(&timestamp_str).unwrap());
        headers.insert(
            "MCC-Authentication",
            HeaderValue::from_str(&sig_head_str).unwrap(),
        );
    }

    const MAUTH_ENCODE_CHARS: &'static AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'%')
        .remove(b'.')
        .remove(b'~');

    fn encode_query(qstr: &str) -> String {
        let mut temp_param_list: Vec<Vec<Vec<u8>>> = qstr
            .split('&')
            .map(|p| {
                p.split('=')
                    .map(|x| percent_decode_str(&x.replace("+", " ")).collect())
                    .collect()
            })
            .collect();

        temp_param_list.sort();
        temp_param_list
            .iter()
            .map(|p| {
                p.iter()
                    .map(|x| percent_encode(&x, Self::MAUTH_ENCODE_CHARS).to_string())
                    .collect::<Vec<String>>()
                    .join("=")
            })
            .collect::<Vec<String>>()
            .join("&")
    }

    fn normalize_url(urlstr: &str) -> String {
        let squeeze_regex = Regex::new(r"/+").unwrap();
        let url = squeeze_regex.replace_all(urlstr, "/");
        let percent_case_regex = Regex::new(r"%[a-f0-9]{2}").unwrap();
        let url = percent_case_regex.replace_all(&url, |c: &Captures| c[0].to_uppercase());
        let mut url = url.replace("/./", "/");
        let path_regex2 = Regex::new(r"/[^/]+/\.\./?").unwrap();
        loop {
            let new_url = path_regex2.replace_all(&url, "/").to_string();
            if new_url == url {
                return new_url;
            } else {
                url = new_url;
            }
        }
    }

    /// Sign a provided request using the MAuth V1 protocol. The signature consists of 2 headers
    /// containing both a timestamp and a signature string, and will be added to the headers of the
    /// request. It is required to pass a `body`, even if the request is an empty-body GET.
    ///
    /// Note that, as the request signature includes a timestamp, the request must be sent out
    /// shortly after the signature takes place.
    pub fn sign_request_v1(&self, req: &mut Request<Body>, body: &BodyDigest) {
        let timestamp_str = Utc::now().timestamp().to_string();
        let mut hasher = Sha512::default();
        let string_to_sign1 = format!("{}\n{}\n", req.method(), req.uri().path());
        hasher.update(string_to_sign1.into_bytes());
        hasher.update(body.body_data.clone());
        let string_to_sign2 = format!("\n{}\n{}", &self.app_id, &timestamp_str);
        hasher.update(string_to_sign2.into_bytes());

        let mut sign_output = vec![0; self.openssl_private_key.size() as usize];
        self.openssl_private_key
            .private_encrypt(
                &hex::encode(&hasher.finalize()).into_bytes(),
                &mut sign_output,
                Padding::PKCS1,
            )
            .unwrap();
        let signature = format!("MWS {}:{}", self.app_id, base64::encode(&sign_output));

        let headers = req.headers_mut();
        headers.insert("X-MWS-Time", HeaderValue::from_str(&timestamp_str).unwrap());
        headers.insert(
            "X-MWS-Authentication",
            HeaderValue::from_str(&signature).unwrap(),
        );
    }

    fn validate_timestamp(timestamp_str: &str) -> Result<(), MAuthValidationError> {
        let ts_num: i64 = timestamp_str
            .parse()
            .map_err(|_| MAuthValidationError::InvalidTime)?;
        let ts_diff = ts_num - Utc::now().timestamp();
        if ts_diff > 300 || ts_diff < -300 {
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
        let raw_signature: Vec<u8> = base64::decode(&signature_encoded_string)
            .map_err(|_| MAuthValidationError::InvalidSignature)?;
        Ok((host_app_uuid, raw_signature))
    }

    async fn bytes_from_body(mut body: Body) -> Result<Vec<u8>, MAuthValidationError> {
        let mut response_vec = vec![];
        while let Some(chunk) = body.data().await {
            response_vec.extend_from_slice(
                chunk
                    .map_err(|_| MAuthValidationError::ResponseProblem)?
                    .as_ref(),
            );
        }
        Ok(response_vec)
    }

    async fn validate_response_v2(
        &self,
        parts: &http::response::Parts,
        body_raw: &[u8],
    ) -> Result<String, MAuthValidationError> {
        let resp_headers = &parts.headers;

        //retrieve and validate timestamp
        let ts_str = resp_headers
            .get("MCC-Time")
            .ok_or(MAuthValidationError::NoTime)?
            .to_str()
            .map_err(|_| MAuthValidationError::InvalidTime)?;
        Self::validate_timestamp(&ts_str)?;

        //retrieve and parse auth string
        let sig_header = resp_headers
            .get("MCC-Authentication")
            .ok_or(MAuthValidationError::NoSig)?
            .to_str()
            .map_err(|_| MAuthValidationError::InvalidSignature)?;
        let (host_app_uuid, raw_signature) = Self::split_auth_string(&sig_header, "MWSV2")?;

        //Compute response signing string
        let mut hasher = Sha512::default();
        hasher.update(&body_raw);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            &parts.status.as_u16(),
            hex::encode(hasher.finalize()),
            &host_app_uuid,
            &ts_str,
        );

        match self.get_app_pub_key(&host_app_uuid).await {
            None => Err(MAuthValidationError::KeyUnavailable),
            Some(pub_key) => {
                let ring_key = UnparsedPublicKey::new(
                    &RSA_PKCS1_2048_8192_SHA512,
                    bytes::Bytes::from(pub_key.public_key_to_der_pkcs1().unwrap()),
                );
                match ring_key.verify(&string_to_sign.into_bytes(), &raw_signature) {
                    Ok(()) => String::from_utf8(body_raw.to_vec())
                        .map_err(|_| MAuthValidationError::InvalidBody),
                    Err(_) => Err(MAuthValidationError::SignatureVerifyFailure),
                }
            }
        }
    }

    async fn validate_response_v1(
        &self,
        parts: &http::response::Parts,
        body_raw: &[u8],
    ) -> Result<String, MAuthValidationError> {
        let resp_headers = &parts.headers;

        //retrieve and validate timestamp
        let ts_str = resp_headers
            .get("X-MWS-Time")
            .ok_or(MAuthValidationError::NoTime)?
            .to_str()
            .map_err(|_| MAuthValidationError::InvalidTime)?;
        Self::validate_timestamp(&ts_str)?;

        //retrieve and parse auth string
        let sig_header = resp_headers
            .get("X-MWS-Authentication")
            .ok_or(MAuthValidationError::NoSig)?
            .to_str()
            .map_err(|_| MAuthValidationError::InvalidSignature)?;
        let (host_app_uuid, raw_signature) = Self::split_auth_string(&sig_header, "MWS")?;

        //Build signature string and hash to final format
        let mut hasher = Sha512::default();
        let string1 = format!("{}\n", &parts.status.as_u16());
        hasher.update(&string1.into_bytes());
        hasher.update(&body_raw);
        let string2 = format!("\n{}\n{}", &host_app_uuid, &ts_str);
        hasher.update(&string2.into_bytes());
        let sign_input: Vec<u8> = hex::encode(hasher.finalize()).into_bytes();

        //Decrypt signature from server
        let pub_key = self
            .get_app_pub_key(&host_app_uuid)
            .await
            .ok_or(MAuthValidationError::KeyUnavailable)?;
        let mut sign_output: Vec<u8> = vec![0; pub_key.size() as usize];
        let len = pub_key
            .public_decrypt(&raw_signature, &mut sign_output, Padding::PKCS1)
            .unwrap();

        if *sign_input.as_slice() == sign_output[0..len] {
            let body_str = String::from_utf8(body_raw.to_vec())
                .map_err(|_| MAuthValidationError::InvalidBody)?;
            Ok(body_str)
        } else {
            Err(MAuthValidationError::SignatureVerifyFailure)
        }
    }

    async fn get_app_pub_key(&self, app_uuid: &Uuid) -> Option<Rsa<Public>> {
        let mut key_store = self.remote_key_store.borrow_mut();
        if let Some(pub_key) = key_store.get(&app_uuid) {
            return Some(pub_key.clone());
        }
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);
        let (get_body, body_digest) = MAuthInfo::build_body_with_digest("".to_string());
        let mut req = Request::new(get_body);
        *req.method_mut() = Method::GET;
        let mut uri_parts = self.mauth_uri_base.clone().into_parts();
        let mut path_str: String = uri_parts
            .path_and_query
            .take()
            .unwrap()
            .as_str()
            .to_string();
        path_str.push_str(&format!("{}", &app_uuid));
        uri_parts.path_and_query = Some(path_str.parse().unwrap());
        let uri = hyper::Uri::from_parts(uri_parts).unwrap();
        *req.uri_mut() = uri;
        self.sign_request_v2(&mut req, &body_digest);
        let mauth_response = client.request(req).await;
        match mauth_response {
            Err(_) => None,
            Ok(response) => {
                let response_str =
                    String::from_utf8(Self::bytes_from_body(response.into_body()).await.unwrap())
                        .unwrap();
                let response_obj: serde_json::Value = serde_json::from_str(&response_str).unwrap();
                let pub_key_str = response_obj
                    .pointer("/security_token/public_key_str")
                    .and_then(|s| s.as_str())
                    .unwrap();
                let pub_key = Rsa::public_key_from_pem(&pub_key_str.as_bytes()).unwrap();
                key_store.insert(*app_uuid, pub_key.clone());
                Some(pub_key)
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
#[derive(Debug)]
pub enum ConfigReadError {
    FileReadError(io::Error),
    InvalidFile(Option<serde_yaml::Error>),
    InvalidUri(http::uri::InvalidUri),
    InvalidAppUuid(uuid::Error),
    OpenSSLError(openssl::error::ErrorStack),
    RingKeyError(ring::error::KeyRejected),
}

impl From<io::Error> for ConfigReadError {
    fn from(err: io::Error) -> ConfigReadError {
        ConfigReadError::FileReadError(err)
    }
}

impl From<serde_yaml::Error> for ConfigReadError {
    fn from(err: serde_yaml::Error) -> ConfigReadError {
        ConfigReadError::InvalidFile(Some(err))
    }
}

impl From<http::uri::InvalidUri> for ConfigReadError {
    fn from(err: http::uri::InvalidUri) -> ConfigReadError {
        ConfigReadError::InvalidUri(err)
    }
}

impl From<uuid::Error> for ConfigReadError {
    fn from(err: uuid::Error) -> ConfigReadError {
        ConfigReadError::InvalidAppUuid(err)
    }
}

impl From<openssl::error::ErrorStack> for ConfigReadError {
    fn from(err: openssl::error::ErrorStack) -> ConfigReadError {
        ConfigReadError::OpenSSLError(err)
    }
}

impl From<ring::error::KeyRejected> for ConfigReadError {
    fn from(err: ring::error::KeyRejected) -> ConfigReadError {
        ConfigReadError::RingKeyError(err)
    }
}

/// All of the possible errors that can take place when attempting to verify a response signature
#[derive(Debug)]
pub enum MAuthValidationError {
    /// The timestamp of the response was either invalid or outside of the permitted
    /// range
    InvalidTime,
    /// The MAuth signature of the response was either missing or incorrectly formatted
    InvalidSignature,
    /// The timestamp header of the response was missing
    NoTime,
    /// The signature header of the response was missing
    NoSig,
    /// An error occurred while attempting to retrieve part of the response body
    ResponseProblem,
    /// The response body failed to parse
    InvalidBody,
    /// Attempt to retrieve a key to verify the response failed
    KeyUnavailable,
    /// The body of the response did not match the signature
    SignatureVerifyFailure,
}
