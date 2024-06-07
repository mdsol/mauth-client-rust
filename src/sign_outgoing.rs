use crate::MAuthInfo;
use chrono::prelude::*;
use reqwest::{header::HeaderValue, Request};
use thiserror::Error;

impl MAuthInfo {
    /// This method determines how to sign the request automatically while respecting the
    /// `v2_only_sign_requests` flag in the config file. It always signs with the V2 algorithm and
    /// signature, and will also sign with the V1 algorithm, if the configuration permits.
    ///
    /// Note that, as the request signature includes a timestamp, the request must be sent out
    /// shortly after the signature takes place.
    /// 
    /// Note that it will need to read the entire body in order to sign it, so it will not
    /// work properly if any of the streaming body types are used.
    pub fn sign_request(&self, req: &mut Request) -> Result<(), SigningError> {
        self.sign_request_v2(req)?;
        if self.sign_with_v1_also {
            self.sign_request_v1(req)?;
        }
        Ok(())
    }

    /// Sign a provided request using the MAuth V2 protocol. The signature consists of 2 headers
    /// containing both a timestamp and a signature string, and will be added to the headers of the
    /// request. It is required to pass a `body_digest` computed by the
    /// [`build_body_with_digest`](#method.build_body_with_digest) method, even if the request is
    /// an empty-body GET.
    ///
    /// Note that, as the request signature includes a timestamp, the request must be sent out
    /// shortly after the signature takes place.
    /// 
    /// Also note that it will need to read the entire body in order to sign it, so it will not
    /// work properly if any of the streaming body types are used.
    pub fn sign_request_v2(&self, req: &mut Request) -> Result<(), SigningError> {
        let timestamp_str = Utc::now().timestamp().to_string();
        let body_data = match req.body() {
            None => &[],
            Some(reqwest_body) => reqwest_body.as_bytes().unwrap_or(&[]),
        };
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

    pub(crate) fn set_headers_v2(&self, req: &mut Request, signature: String, timestamp_str: &str) {
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
    /// 
    /// Also note that it will need to read the entire body in order to sign it, so it will not
    /// work properly if any of the streaming body types are used.
    pub fn sign_request_v1(&self, req: &mut Request) -> Result<(), SigningError> {
        let timestamp_str = Utc::now().timestamp().to_string();

        let body_data = match req.body() {
            None => &[],
            Some(reqwest_body) => reqwest_body.as_bytes().unwrap_or(&[]),
        };

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
