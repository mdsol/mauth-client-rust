//! # mauth-client-rust
//!
//! This crate allows users of the Hyper crate for making HTTP requests to sign those requests with
//! the MAuth protocol, and verify the responses. Usage example:
//!
//! ```no_run
//! # use mauth_client_rust::MAuthInfo;
//! # use hyper::{Body, Client, Method, Request, Response};
//! # use hyper_tls::HttpsConnector;
//! # async fn make_signed_request() {
//! let mauth_info = MAuthInfo::from_default_file().await.unwrap();
//! let https = HttpsConnector::new();
//! let client = Client::builder().build::<_, hyper::Body>(https);
//! let uri: hyper::Uri = "https://www.example.com/".parse().unwrap();
//! let (body, body_digest) = MAuthInfo::build_body_with_digest("".to_string());
//! let mut req = Request::new(body);
//! *req.method_mut() = Method::GET;
//! *req.uri_mut() = uri.clone();
//! mauth_info.sign_request_v2(&mut req, body_digest);
//! match client.request(req).await {
//!     Err(err) => println!("Got error {}", err),
//!     Ok(response) => match mauth_info.validate_response_v2(response).await {
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
use percent_encoding::{percent_encode, AsciiSet, NON_ALPHANUMERIC};
use ring::rand::SystemRandom;
use ring::signature::{
    RsaKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_SHA512,
};
use serde::Deserialize;
use sha2::{Digest, Sha512};
use tokio::fs;
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
}

#[derive(Deserialize)]
struct ConfigFileSection {
    app_uuid: String,
    mauth_baseurl: String,
    mauth_api_version: String,
    private_key_file: String,
}

impl MAuthInfo {
    /// Construct the MAuthInfo struct based on the contents of the config file `.mauth_config.yml`
    /// present in the current user's home directory. Currently returns a string error in case of
    /// any failures in loading the file or processing the URL, UUID, or private key specified in
    /// it.
    pub async fn from_default_file() -> Result<MAuthInfo, String> {
        let mut home = dirs::home_dir().unwrap();
        home.push(CONFIG_FILE);
        let config_data = fs::read(&home)
            .await
            .map_err(|_| "Couldn't open config file")?;

        let section: ConfigFileSection = serde_yaml::from_slice::<serde_yaml::Value>(&config_data)
            .ok()
            .and_then(|config| {
                config
                    .get("common")
                    .and_then(|section| serde_yaml::from_value(section.clone()).ok())
            })
            .ok_or("Invalid config file format")?;

        let full_uri: hyper::Uri = format!(
            "{}/mauth/{}/security_tokens/",
            &section.mauth_baseurl, &section.mauth_api_version
        )
        .parse()
        .map_err(|_| "Invalid config file format")?;

        let pk_data = fs::read(&section.private_key_file)
            .await
            .map_err(|_| "Couldn't open key file")?;
        let openssl_key = PKey::private_key_from_pem(&pk_data)
            .map_err(|e| format!("OpenSSL Key Load Error: {}", e))?;
        let der_key_data = openssl_key.private_key_to_der().unwrap();

        Ok(MAuthInfo {
            app_id: Uuid::parse_str(&section.app_uuid)
                .map_err(|_| "UUID from config file was bad")?,
            mauth_uri_base: full_uri,
            remote_key_store: RefCell::new(HashMap::new()),
            private_key: RsaKeyPair::from_der(&der_key_data).map_err(|_| "Invalid private key")?,
            openssl_private_key: openssl_key.rsa().map_err(|_| "Invalid private key")?,
        })
    }

    /// The MAuth Protocol requires computing a digest of the full text body of the request to be
    /// sent. This is incompatible with the Hyper crate's structs, which do not allow the body of a
    /// constructed Request to be read. To solve this, use this function to compute both the body to
    /// be used to build the Request struct, and the digest to be passed to the
    /// [`sign_request_v2`](#method.sign_request_v2) function.
    ///
    /// Note that this method must be used with all empty-body requests, including GET requests.
    pub fn build_body_with_digest(body: String) -> (Body, String) {
        let mut hasher = Sha512::default();
        hasher.input(body.as_bytes());
        (Body::from(body), hex::encode(hasher.result()))
    }

    /// Sign a provided request using the MAuth V2 protocol. The signature consists of 2 headers
    /// containing both a timestamp and a signature string, and will be added to the headers of the
    /// request. It is required to pass a `body_digest` computed by the
    /// [`build_body_with_digest`](#method.build_body_with_digest) method, even if the request is
    /// an empty-body GET.
    ///
    /// Note that, as the request signature includes a timestamp, the request must be sent out
    /// shortly after the signature takes place.
    pub fn sign_request_v2(&self, req: &mut Request<Body>, body_digest: String) {
        let timestamp_str = Utc::now().timestamp().to_string();
        let encoded_query: String = req
            .uri()
            .query()
            .map_or("".to_string(), |q| Self::encode_query(q));
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            req.method(),
            req.uri().path(),
            &body_digest,
            &self.app_id,
            &timestamp_str,
            &encoded_query
        );

        let mut signature = vec![0; self.private_key.public_modulus_len()];
        self.private_key
            .sign(
                &RSA_PKCS1_SHA512,
                &SystemRandom::new(),
                string_to_sign.as_bytes(),
                &mut signature,
            )
            .unwrap();
        let signature = format!("MWSV2 {}:{};", self.app_id, base64::encode(&signature));

        let headers = req.headers_mut();
        headers.insert("MCC-Time", HeaderValue::from_str(&timestamp_str).unwrap());
        headers.insert(
            "MCC-Authentication",
            HeaderValue::from_str(&signature).unwrap(),
        );
    }

    const MAUTH_ENCODE_CHARS: &'static AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');

    fn encode_query(qstr: &str) -> String {
        let mut s: Vec<String> = qstr.split('&').map(|p| p.to_owned()).collect();
        s.sort();
        s.iter()
            .map(|p| {
                p.split('=')
                    .map(|x| percent_encode(x.as_bytes(), Self::MAUTH_ENCODE_CHARS).to_string())
                    .collect::<Vec<String>>()
                    .join("=")
            })
            .collect::<Vec<String>>()
            .join("&")
    }

    /// Sign a provided request using the MAuth V1 protocol. The signature consists of 2 headers
    /// containing both a timestamp and a signature string, and will be added to the headers of the
    /// request. It is required to pass a `body`, even if the request is an empty-body GET.
    ///
    /// Note that, as the request signature includes a timestamp, the request must be sent out
    /// shortly after the signature takes place.
    pub fn sign_request_v1(&self, req: &mut Request<Body>, body: String) {
        let timestamp_str = Utc::now().timestamp().to_string();
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            req.method(),
            req.uri().path(),
            &body,
            &self.app_id,
            &timestamp_str,
        );

        let mut hasher = Sha512::default();
        hasher.input(string_to_sign.as_bytes());
        let mut sign_output = vec![0; self.openssl_private_key.size() as usize];
        self.openssl_private_key
            .private_encrypt(&hasher.result(), &mut sign_output, Padding::PKCS1)
            .unwrap();
        let signature = format!("MWS {}:{}", self.app_id, base64::encode(&sign_output));

        let headers = req.headers_mut();
        headers.insert("X-MWS-TIME", HeaderValue::from_str(&timestamp_str).unwrap());
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

    fn split_auth_string(auth_str: &str) -> Result<(Uuid, Vec<u8>), MAuthValidationError> {
        let header_pattern = vec![' ', ':', ';'];
        let mut header_split = auth_str.split(header_pattern.as_slice());

        let start_str = header_split
            .next()
            .ok_or(MAuthValidationError::InvalidSignature)?;
        if start_str != "MWSV2" {
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

    /// Validate that a Hyper Response contains a valid MAuth V2 signature. Returns either the
    /// validated response body, or an error with details on why the signature was invalid.
    ///
    /// This method is `async` because it may make a HTTP request to the MAuth server in order to
    /// retrieve the public key for the application that signed the response. Application keys are
    /// cached in the MAuth struct, so the request only needs to be made once.
    pub async fn validate_response_v2(
        &self,
        response: Response<Body>,
    ) -> Result<String, MAuthValidationError> {
        let (parts, body) = response.into_parts();
        let resp_headers = parts.headers;

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
        let (host_app_uuid, raw_signature) = Self::split_auth_string(&sig_header)?;

        //Compute response signing string
        let body_raw: Vec<u8> = Self::bytes_from_body(body).await?;
        let mut hasher = Sha512::default();
        hasher.input(&body_raw);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            &parts.status.as_u16(),
            hex::encode(hasher.result()),
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
                match ring_key.verify(&string_to_sign.as_bytes(), &raw_signature) {
                    Ok(()) => {
                        String::from_utf8(body_raw).map_err(|_| MAuthValidationError::InvalidBody)
                    }
                    Err(_) => Err(MAuthValidationError::SignatureVerifyFailure),
                }
            }
        }
    }

    /// Validate that a Hyper Response contains a valid MAuth V1 signature. Returns either the
    /// validated response body, or an error with details on why the signature was invalid.
    ///
    /// **Warning, this method does not currently work correctly**
    ///
    /// This method is `async` because it may make a HTTP request to the MAuth server in order to
    /// retrieve the public key for the application that signed the response. Application keys are
    /// cached in the MAuth struct, so the request only needs to be made once.
    pub async fn validate_response_v1(
        &self,
        response: Response<Body>,
    ) -> Result<String, MAuthValidationError> {
        let (parts, body) = response.into_parts();
        let resp_headers = parts.headers;

        let body_raw: Vec<u8> = Self::bytes_from_body(body).await?;
        let body_str =
            String::from_utf8(body_raw.clone()).map_err(|_| MAuthValidationError::InvalidBody)?;
        println!("Response body is {}", &body_str);

        for hkey in resp_headers.keys() {
            println!("Has response header '{}'", hkey.as_str());
        }

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
        let (host_app_uuid, raw_signature) = Self::split_auth_string(&sig_header)?;

        let mut hasher = Sha512::default();
        hasher.input(&body_raw);
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            &parts.status.as_u16(),
            hex::encode(hasher.result()),
            &host_app_uuid,
            &ts_str,
        );

        let mut hasher2 = Sha512::default();
        hasher2.input(&string_to_sign.as_bytes());
        let sign_input = hasher2.result();
        let pub_key = self
            .get_app_pub_key(&host_app_uuid)
            .await
            .ok_or(MAuthValidationError::KeyUnavailable)?;
        let mut sign_output = vec![0; self.openssl_private_key.size() as usize];
        pub_key
            .public_decrypt(&raw_signature, &mut sign_output, Padding::PKCS1)
            .unwrap();

        if sign_input.len() == sign_output.len() {
            Ok(body_str)
        } else {
            Err(MAuthValidationError::SignatureVerifyFailure)
        }

        /*match self.get_app_pub_key(&host_app_uuid, &mut runtime) {
            None => return Err(MAuthValidationError::KeyUnavailable),
            Some(pub_key) => match pub_key.verify(&string_to_sign.as_bytes(), &raw_signature) {
                Ok(()) => {
                    String::from_utf8(body_raw).map_err(|_| MAuthValidationError::InvalidBody)
                }
                Err(_) => Err(MAuthValidationError::SignatureVerifyFailure),
            },
        }*/
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
        self.sign_request_v2(&mut req, body_digest);
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
                key_store.insert(app_uuid.clone(), pub_key.clone());
                Some(pub_key)
            }
        }
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
