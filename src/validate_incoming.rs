use crate::MAuthInfo;
use base64::Engine;
use chrono::prelude::*;
use mauth_core::verifier::Verifier;
use reqwest::{Client, Method, Request};
use thiserror::Error;
use uuid::Uuid;

/// This struct holds the app UUID for a validated request. It is meant to be used with the
/// Extension setup in Hyper requests, where it is placed in requests that passed authentication.
/// The custom struct makes it clearer that the request has passed and this is an authenticated
/// app UUID and not some random UUID that some other component put in place for some other
/// purpose.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ValidatedRequestDetails {
    pub app_uuid: Uuid,
}

impl MAuthInfo {
    pub(crate) async fn validate_request(
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

    async fn validate_request_v2(
        &self,
        req: &http::request::Parts,
        body_bytes: &bytes::Bytes,
    ) -> Result<Uuid, MAuthValidationError> {
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
        self.sign_request_v2(&mut req).unwrap();
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
