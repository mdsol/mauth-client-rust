use crate::{CLIENT, MAuthInfo, pubkey_cache};
use axum::extract::Request;
use bytes::Bytes;
use chrono::prelude::*;
use http::{HeaderMap, StatusCode, header};
use lru::LruCache;
use mauth_core::verifier::Verifier;
use std::num::NonZeroUsize;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::error;
use uuid::Uuid;

/// How many verifier keys are retained before the least recently used is
/// dropped.
///
/// This crate is used by every MAuth-authenticating service, so this is sized
/// for a wide-fanout gateway rather than a small API. Entries cost roughly a
/// kilobyte each, and only apps that actually call the service occupy one --
/// lookups that MAuth answers with a 404 are never stored -- so the cache
/// cannot be grown by an unregistered caller. Override with
/// `ConfigFileSection::pubkey_cache_capacity` where the default does not fit.
pub(crate) const DEFAULT_PUBKEY_CACHE_CAPACITY: usize = 10_000;

/// How long a key is trusted when MAuth does not say.
///
/// Matches the MAuth service's own `TOKEN_EXPIRATION` default, so a response
/// that arrives without usable cache headers is treated the way an unconfigured
/// MAuth would have asked for.
const FALLBACK_KEY_LIFETIME: Duration = Duration::from_secs(60);

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

/// The app UUID a request *claimed*, read from its MAuth signature header
/// without verifying anything.
///
/// This is deliberately a separate type from [`ValidatedRequestDetails`],
/// because it is not an authenticated identity: it is attached to requests that
/// **failed** validation, so that a rejection can be attributed in logs.
/// Anything making a trust decision must use [`ValidatedRequestDetails`].
///
/// Found in the extensions of the `401` response for the required-validation
/// layer, and in the request extensions for the optional one.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AttemptedMAuthIdentity {
    pub app_uuid: Uuid,
}

/// A request that failed validation, along with the identity it claimed.
pub(crate) struct RejectedRequest {
    pub(crate) error: MAuthValidationError,
    pub(crate) app_uuid: Option<Uuid>,
}

const MAUTH_V1_SIGNATURE_HEADER: &str = "X-MWS-Authentication";
const MAUTH_V2_SIGNATURE_HEADER: &str = "MCC-Authentication";
const MAUTH_V1_TIMESTAMP_HEADER: &str = "X-MWS-Time";
const MAUTH_V2_TIMESTAMP_HEADER: &str = "MCC-Time";

impl MAuthInfo {
    pub(crate) async fn validate_request(&self, req: Request) -> Result<Request, RejectedRequest> {
        let (mut parts, body) = req.into_parts();
        // Read the claimed identity up front. On the required-validation path
        // the request is dropped when we reject it, so this is the only chance
        // to capture who was turned away.
        let attempted = Self::attempted_app_uuid(&parts.headers);
        let reject = |error| RejectedRequest {
            error,
            app_uuid: attempted,
        };
        let body_bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|_| reject(MAuthValidationError::InvalidBody))?;
        match self.validate_request_v2(&parts, &body_bytes).await {
            Ok(host_app_uuid) => {
                parts.extensions.insert(ValidatedRequestDetails {
                    app_uuid: host_app_uuid,
                });
                let new_body = axum::body::Body::from(body_bytes);
                let new_request = Request::from_parts(parts, new_body);
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
                            let new_request = Request::from_parts(parts, new_body);
                            Ok(new_request)
                        }
                        Err(err) => Err(reject(err)),
                    }
                } else {
                    Err(reject(err))
                }
            }
        }
    }

    pub(crate) async fn validate_request_optionally(&self, req: Request) -> Request {
        let (mut parts, body) = req.into_parts();
        if parts.headers.contains_key(MAUTH_V2_SIGNATURE_HEADER)
            || parts.headers.contains_key(MAUTH_V1_SIGNATURE_HEADER)
        {
            // By my reading of the code for this it should never fail, since we are passing
            // MAX for the limit. But just to be safe, we will log the error and proceed with
            // an empty body just in case instead of unwrapping. This would cause the body to
            // be unavailable to the lower layers, but they would probably also fail to get it
            // anyways since we just did here.
            let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    error!(
                        ?error,
                        "Failed to retrieve request body, continuing with empty body"
                    );
                    Bytes::new()
                }
            };

            let attempted = Self::attempted_app_uuid(&parts.headers);

            match self.validate_request_v2(&parts, &body_bytes).await {
                Ok(host_app_uuid) => {
                    parts.extensions.insert(ValidatedRequestDetails {
                        app_uuid: host_app_uuid,
                    });
                }
                Err(error_v2) => {
                    if self.allow_v1_auth {
                        match self.validate_request_v1(&parts, &body_bytes).await {
                            Ok(host_app_uuid) => {
                                parts.extensions.insert(ValidatedRequestDetails {
                                    app_uuid: host_app_uuid,
                                });
                            }
                            Err(error_v1) => {
                                error!(
                                    ?error_v2,
                                    ?error_v1,
                                    app_uuid = attempted.map(tracing::field::display),
                                    "Error attempting to validate MAuth signatures"
                                );
                                Self::record_attempted_identity(&mut parts, attempted);
                                parts.extensions.insert(error_v1);
                            }
                        }
                    } else {
                        error!(
                            ?error_v2,
                            app_uuid = attempted.map(tracing::field::display),
                            "Error attempting to validate MAuth V2 signature"
                        );
                        Self::record_attempted_identity(&mut parts, attempted);
                        parts.extensions.insert(error_v2);
                    }
                }
            }

            let new_body = axum::body::Body::from(body_bytes);
            Request::from_parts(parts, new_body)
        } else {
            Request::from_parts(parts, body)
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
            .get(MAUTH_V2_SIGNATURE_HEADER)
            .ok_or(MAuthValidationError::NoSig)?
            .to_str()
            .map_err(|_| MAuthValidationError::InvalidSignature)?;
        let (host_app_uuid, raw_signature) = Self::split_auth_string(sig_header, "MWSV2")?;

        //retrieve and validate timestamp
        let ts_str = req
            .headers
            .get(MAUTH_V2_TIMESTAMP_HEADER)
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
            .get(MAUTH_V1_SIGNATURE_HEADER)
            .ok_or(MAuthValidationError::NoSig)?
            .to_str()
            .map_err(|_| MAuthValidationError::InvalidSignature)?;
        let (host_app_uuid, raw_signature) = Self::split_auth_string(sig_header, "MWS")?;

        //retrieve and validate timestamp
        let ts_str = req
            .headers
            .get(MAUTH_V1_TIMESTAMP_HEADER)
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
        Ok((host_app_uuid, signature_encoded_string.into()))
    }

    /// The app UUID a request claims, taken straight from its signature header
    /// with no verification at all.
    ///
    /// Prefers the V2 header when both are present, matching the order the
    /// validation paths try them in. Never use the result as an identity.
    fn attempted_app_uuid(headers: &HeaderMap) -> Option<Uuid> {
        let (header_name, token) = if headers.contains_key(MAUTH_V2_SIGNATURE_HEADER) {
            (MAUTH_V2_SIGNATURE_HEADER, "MWSV2")
        } else {
            (MAUTH_V1_SIGNATURE_HEADER, "MWS")
        };
        let header_value = headers.get(header_name)?.to_str().ok()?;
        Self::split_auth_string(header_value, token)
            .ok()
            .map(|(app_uuid, _)| app_uuid)
    }

    /// Attach the claimed identity to a request that failed validation, so an
    /// outer logging layer can attribute the rejection.
    fn record_attempted_identity(parts: &mut http::request::Parts, app_uuid: Option<Uuid>) {
        if let Some(app_uuid) = app_uuid {
            parts.extensions.insert(AttemptedMAuthIdentity { app_uuid });
        }
    }

    async fn get_app_pub_key(&self, app_uuid: &Uuid) -> Option<Verifier> {
        if let Some(verifier) = pubkey_cache().get(app_uuid, Instant::now()) {
            return Some(verifier);
        }

        let uri = self.mauth_uri_base.join(&format!("{}", app_uuid)).unwrap();
        let request_started = Instant::now();
        let response = CLIENT.get().unwrap().get(uri).send().await.ok()?;

        // Only a 200 carries a key. Checking explicitly keeps a 404 -- which
        // means "no such app" -- from being distinguished only by a later
        // pointer lookup happening to miss.
        if response.status() != StatusCode::OK {
            return None;
        }
        // `json` consumes the response, so decide the freshness first.
        let freshness = cacheable_until(response.headers(), request_started, Instant::now());

        let response_obj = response.json::<serde_json::Value>().await.ok()?;
        let pub_key_str = response_obj
            .pointer("/security_token/public_key_str")
            .and_then(|s| s.as_str())?;
        let verifier = Verifier::new(*app_uuid, pub_key_str.to_owned()).ok()?;

        if let Freshness::Until(expires_at) = freshness {
            pubkey_cache().put(*app_uuid, verifier.clone(), expires_at);
        }
        Some(verifier)
    }
}

/// How long a fetched key may be reused, if at all.
#[derive(Debug, PartialEq, Eq)]
enum Freshness {
    /// Reusable until this moment.
    Until(Instant),
    /// The origin forbade reuse, or the response was already stale on arrival.
    DoNotStore,
}

/// When a MAuth response stops being reusable.
///
/// MAuth states its own policy -- `max-age=300, public` on a hit today, though
/// the service reads that from an environment variable and its own default is
/// 60 -- so this honors what the origin says rather than assuming a number. A
/// response with no usable directive falls back to [`FALLBACK_KEY_LIFETIME`],
/// which keeps MAuth from becoming a synchronous dependency of every single
/// authenticated request if those headers ever regress.
fn cacheable_until(headers: &HeaderMap, request_started: Instant, now: Instant) -> Freshness {
    let fallback = Freshness::Until(now + FALLBACK_KEY_LIFETIME);

    let Some(cache_control) = headers.get(header::CACHE_CONTROL) else {
        return fallback;
    };
    let Ok(cache_control) = cache_control.to_str() else {
        return fallback;
    };

    let mut max_age: Option<Duration> = None;
    for directive in cache_control.split(',') {
        let directive = directive.trim();
        // `no-cache` permits storage with revalidation, which this cache has no
        // way to do -- MAuth sends no ETag on the responses that carry it -- so
        // treat it the same as `no-store`. This is the path a 404 takes.
        if directive.eq_ignore_ascii_case("no-store") || directive.eq_ignore_ascii_case("no-cache")
        {
            return Freshness::DoNotStore;
        }
        if let Some((name, seconds)) = directive.split_once('=')
            && name.trim().eq_ignore_ascii_case("max-age")
            && let Ok(seconds) = seconds.trim().trim_matches('"').parse::<u64>()
        {
            // Take the shortest of any repeats, so `max-age=0, max-age=300`
            // is not treated as reusable.
            let stated = Duration::from_secs(seconds);
            max_age = Some(max_age.map_or(stated, |seen: Duration| seen.min(stated)));
        }
    }

    let Some(max_age) = max_age else {
        return fallback;
    };

    // RFC 9111 4.2.3, simplified: what the origin says the response has
    // already aged, plus how long it spent reaching us.
    let age = headers
        .get(header::AGE)
        .and_then(|age| age.to_str().ok())
        .and_then(|age| age.trim().parse::<u64>().ok())
        .map_or(Duration::ZERO, Duration::from_secs)
        + now.saturating_duration_since(request_started);

    match max_age.checked_sub(age) {
        Some(remaining) if !remaining.is_zero() => Freshness::Until(now + remaining),
        _ => Freshness::DoNotStore,
    }
}

/// A bounded, expiring store of verifier keys.
///
/// Both bounds matter. The expiry is the point: without it a key rotation
/// leaves every long-lived process rejecting the rotated app forever. The
/// capacity is a safety net -- entries can only be created for registered apps
/// that actually call this service, since failed lookups are never stored.
pub(crate) struct PubkeyCache(Mutex<LruCache<Uuid, (Verifier, Instant)>>);

impl PubkeyCache {
    pub(crate) fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity)
            .unwrap_or(NonZeroUsize::new(DEFAULT_PUBKEY_CACHE_CAPACITY).unwrap());
        Self(Mutex::new(LruCache::new(capacity)))
    }

    fn lock(&self) -> MutexGuard<'_, LruCache<Uuid, (Verifier, Instant)>> {
        // A panic while holding this lock cannot leave the cache unsound -- at
        // worst an insert did not land -- so recover rather than propagating
        // the poison and taking down authentication with it.
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The key for `app_uuid`, if one is cached and still fresh. A hit promotes
    /// recency, so a steady caller is not evicted by a burst of one-off ones.
    fn get(&self, app_uuid: &Uuid, now: Instant) -> Option<Verifier> {
        let mut cache = self.lock();
        let expires_at = cache.peek(app_uuid).map(|(_, expires_at)| *expires_at)?;
        if now >= expires_at {
            cache.pop(app_uuid);
            return None;
        }
        cache.get(app_uuid).map(|(verifier, _)| verifier.clone())
    }

    fn put(&self, app_uuid: Uuid, verifier: Verifier, expires_at: Instant) {
        self.lock().put(app_uuid, (verifier, expires_at));
    }
}

/// All of the possible errors that can take place when attempting to verify a response signature
#[derive(Debug, Error, Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderName;

    const APP_UUID: &str = "66de0549-f7ea-4f17-9984-10643f3357d1";
    const OTHER_UUID: &str = "b0021882-1049-495d-99d7-9df99a78c0e0";

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        headers
    }

    fn verifier(app_uuid: Uuid) -> Verifier {
        let public_key =
            std::fs::read_to_string("mauth-protocol-test-suite/signing-params/rsa-key-pub")
                .unwrap();
        Verifier::new(app_uuid, public_key).unwrap()
    }

    #[test]
    fn cache_lifetime_follows_what_mauth_states() {
        let now = Instant::now();
        let secs = Duration::from_secs;
        let cases: [(&[(&str, &str)], Freshness); 10] = [
            // What MAuth actually sends on a hit today.
            (
                &[("cache-control", "max-age=300, public")],
                Freshness::Until(now + secs(300)),
            ),
            // What it sends on a 404, and the reason unknown apps are not
            // negatively cached.
            (&[("cache-control", "no-cache")], Freshness::DoNotStore),
            (&[("cache-control", "no-store")], Freshness::DoNotStore),
            // An explicit directive beats any max-age beside it.
            (
                &[("cache-control", "no-cache, max-age=300")],
                Freshness::DoNotStore,
            ),
            // Shortest repeat wins, so this is not treated as reusable.
            (
                &[("cache-control", "max-age=0, max-age=300")],
                Freshness::DoNotStore,
            ),
            (
                &[("cache-control", "max-age=300, max-age=60")],
                Freshness::Until(now + secs(60)),
            ),
            // Already partly aged upstream.
            (
                &[("cache-control", "max-age=300"), ("age", "60")],
                Freshness::Until(now + secs(240)),
            ),
            // Aged past its own lifetime before reaching us.
            (
                &[("cache-control", "max-age=60"), ("age", "300")],
                Freshness::DoNotStore,
            ),
            // No usable directive falls back rather than making MAuth a
            // dependency of every authenticated request.
            (&[], Freshness::Until(now + FALLBACK_KEY_LIFETIME)),
            (
                &[("cache-control", "max-age=not-a-number")],
                Freshness::Until(now + FALLBACK_KEY_LIFETIME),
            ),
        ];

        for (pairs, expected) in cases {
            assert_eq!(
                cacheable_until(&headers(pairs), now, now),
                expected,
                "headers: {pairs:?}"
            );
        }
    }

    #[test]
    fn time_in_flight_counts_against_the_stated_lifetime() {
        let started = Instant::now();
        let now = started + Duration::from_secs(10);

        assert_eq!(
            cacheable_until(&headers(&[("cache-control", "max-age=300")]), started, now),
            Freshness::Until(now + Duration::from_secs(290)),
        );
    }

    #[test]
    fn a_cached_key_is_returned_until_it_expires() {
        let app_uuid = Uuid::parse_str(APP_UUID).unwrap();
        let base = Instant::now();
        let cache = PubkeyCache::new(4);

        cache.put(
            app_uuid,
            verifier(app_uuid),
            base + Duration::from_secs(300),
        );

        assert!(cache.get(&app_uuid, base).is_some());
        assert!(
            cache
                .get(&app_uuid, base + Duration::from_secs(299))
                .is_some()
        );
    }

    #[test]
    fn an_expired_key_is_a_miss_and_is_dropped() {
        let app_uuid = Uuid::parse_str(APP_UUID).unwrap();
        let base = Instant::now();
        let cache = PubkeyCache::new(4);

        cache.put(
            app_uuid,
            verifier(app_uuid),
            base + Duration::from_secs(300),
        );

        // This is the rotation case: the key is present but no longer trusted,
        // so the caller re-fetches instead of rejecting the app forever.
        assert!(
            cache
                .get(&app_uuid, base + Duration::from_secs(300))
                .is_none()
        );
        assert!(cache.lock().peek(&app_uuid).is_none());
    }

    #[test]
    fn capacity_evicts_the_least_recently_used() {
        let base = Instant::now();
        let expires_at = base + Duration::from_secs(300);
        let cache = PubkeyCache::new(1);

        let first = Uuid::parse_str(APP_UUID).unwrap();
        let second = Uuid::parse_str(OTHER_UUID).unwrap();
        cache.put(first, verifier(first), expires_at);
        cache.put(second, verifier(second), expires_at);

        assert!(cache.get(&first, base).is_none());
        assert!(cache.get(&second, base).is_some());
    }

    #[test]
    fn reading_a_key_protects_it_from_eviction() {
        let base = Instant::now();
        let expires_at = base + Duration::from_secs(300);
        let cache = PubkeyCache::new(2);

        let steady = Uuid::parse_str(APP_UUID).unwrap();
        let other = Uuid::parse_str(OTHER_UUID).unwrap();
        let one_off = Uuid::new_v4();

        cache.put(steady, verifier(steady), expires_at);
        cache.put(other, verifier(other), expires_at);
        // A steady caller stays resident even as one-off callers churn through.
        assert!(cache.get(&steady, base).is_some());
        cache.put(one_off, verifier(one_off), expires_at);

        assert!(cache.get(&steady, base).is_some());
        assert!(cache.get(&other, base).is_none());
    }

    #[test]
    fn zero_capacity_falls_back_to_the_default() {
        let app_uuid = Uuid::parse_str(APP_UUID).unwrap();
        let base = Instant::now();
        let cache = PubkeyCache::new(0);

        cache.put(
            app_uuid,
            verifier(app_uuid),
            base + Duration::from_secs(300),
        );

        assert!(cache.get(&app_uuid, base).is_some());
    }

    #[test]
    fn attempted_identity_is_read_from_either_signature_header() {
        let expected = Uuid::parse_str(APP_UUID).unwrap();
        let v2 = format!("MWSV2 {APP_UUID}:some-signature;");
        let v1 = format!("MWS {APP_UUID}:some-signature");

        assert_eq!(
            MAuthInfo::attempted_app_uuid(&headers(&[("mcc-authentication", &v2)])),
            Some(expected),
        );
        assert_eq!(
            MAuthInfo::attempted_app_uuid(&headers(&[("x-mws-authentication", &v1)])),
            Some(expected),
        );
    }

    #[test]
    fn attempted_identity_prefers_v2_and_tolerates_junk() {
        let v2 = format!("MWSV2 {APP_UUID}:some-signature;");
        let v1 = format!("MWS {OTHER_UUID}:some-signature");

        assert_eq!(
            MAuthInfo::attempted_app_uuid(&headers(&[
                ("mcc-authentication", &v2),
                ("x-mws-authentication", &v1),
            ])),
            Some(Uuid::parse_str(APP_UUID).unwrap()),
            "V2 is tried first, so it names the identity",
        );

        // A rejection is still a rejection when we cannot say who sent it --
        // these must report no identity rather than fail.
        assert_eq!(MAuthInfo::attempted_app_uuid(&HeaderMap::new()), None);
        assert_eq!(
            MAuthInfo::attempted_app_uuid(&headers(&[("mcc-authentication", "MWSV2 nonsense:x;")])),
            None,
        );
        assert_eq!(
            MAuthInfo::attempted_app_uuid(&headers(&[("mcc-authentication", "garbage")])),
            None,
        );
    }
}
