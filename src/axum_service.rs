//! Structs and impls related to providing a Tower Service and Layer to verify incoming requests

use axum::{
    body::Body,
    extract::{FromRequestParts, OptionalFromRequestParts, Request},
    response::IntoResponse,
};
use futures_core::future::BoxFuture;
use http::{Response, StatusCode, request::Parts};
use std::convert::Infallible;
use std::error::Error;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tracing::error;

use crate::validate_incoming::{MAuthValidationError, ValidatedRequestDetails};
use crate::{
    MAuthInfo,
    config::{ConfigFileSection, ConfigReadError},
};

/// This is a Tower Service which validates that incoming requests have a valid
/// MAuth signature. It only passes the request down to the next layer if the
/// signature is valid, otherwise it returns an appropriate error to the caller.
pub struct RequiredMAuthValidationService<S> {
    mauth_info: MAuthInfo,
    config_info: ConfigFileSection,
    service: S,
}

impl<S> Service<Request> for RequiredMAuthValidationService<S>
where
    S: Service<Request> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn Error + Sync + Send>>,
    S::Response: Into<Response<Body>>,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let mut cloned = self.clone();
        Box::pin(async move {
            match cloned.mauth_info.validate_request(request).await {
                Ok(valid_request) => match cloned.service.call(valid_request).await {
                    Ok(response) => Ok(response.into()),
                    Err(err) => Err(err),
                },
                Err(err) => {
                    error!(
                        error = ?err,
                        "Failed to validate MAuth signature, rejecting request"
                    );
                    Ok(StatusCode::UNAUTHORIZED.into_response())
                }
            }
        })
    }
}

impl<S: Clone> Clone for RequiredMAuthValidationService<S> {
    fn clone(&self) -> Self {
        RequiredMAuthValidationService {
            // unwrap is safe because we validated the config_info before constructing the layer
            mauth_info: MAuthInfo::from_config_section(&self.config_info).unwrap(),
            config_info: self.config_info.clone(),
            service: self.service.clone(),
        }
    }
}

/// This is a Tower Layer which applies the RequiredMAuthValidationService on top of the
/// service provided to it.
#[derive(Clone)]
pub struct RequiredMAuthValidationLayer {
    config_info: ConfigFileSection,
}

impl<S> Layer<S> for RequiredMAuthValidationLayer {
    type Service = RequiredMAuthValidationService<S>;

    fn layer(&self, service: S) -> Self::Service {
        RequiredMAuthValidationService {
            // unwrap is safe because we validated the config_info before constructing the layer
            mauth_info: MAuthInfo::from_config_section(&self.config_info).unwrap(),
            config_info: self.config_info.clone(),
            service,
        }
    }
}

impl RequiredMAuthValidationLayer {
    /// Construct a RequiredMAuthValidationLayer based on the configuration options in the file
    /// found in the default location.
    pub fn from_default_file() -> Result<Self, ConfigReadError> {
        let config_info = MAuthInfo::config_section_from_default_file()?;
        // Generate a MAuthInfo and then drop it to validate that it works,
        // making it safe to use `unwrap` in the service constructor.
        MAuthInfo::from_config_section(&config_info)?;
        Ok(RequiredMAuthValidationLayer { config_info })
    }

    /// Construct a RequiredMAuthValidationLayer based on the configuration options in a manually
    /// created or parsed ConfigFileSection.
    pub fn from_config_section(config_info: ConfigFileSection) -> Result<Self, ConfigReadError> {
        MAuthInfo::from_config_section(&config_info)?;
        Ok(RequiredMAuthValidationLayer { config_info })
    }
}

/// This is a Tower Service which validates that incoming requests have a valid
/// MAuth signature. Unlike the Required service, if this service is not able to
/// find or validate a signature, it passes the request down to the lower layers
/// anyways. This means that it is the responsibility of the request handler to
/// check for the `ValidatedRequestDetails` extension to determine if the request
/// has a valid signature. It also means that this service is safe to attach to
/// the whole application, even if some requests are not validated at all or may
/// be validated in a different way.
pub struct OptionalMAuthValidationService<S> {
    mauth_info: MAuthInfo,
    config_info: ConfigFileSection,
    service: S,
}

impl<S> Service<Request> for OptionalMAuthValidationService<S>
where
    S: Service<Request> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn Error + Sync + Send>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let mut cloned = self.clone();
        Box::pin(async move {
            let processed_request = cloned.mauth_info.validate_request_optionally(request).await;
            cloned.service.call(processed_request).await
        })
    }
}

impl<S: Clone> Clone for OptionalMAuthValidationService<S> {
    fn clone(&self) -> Self {
        OptionalMAuthValidationService {
            // unwrap is safe because we validated the config_info before constructing the layer
            mauth_info: MAuthInfo::from_config_section(&self.config_info).unwrap(),
            config_info: self.config_info.clone(),
            service: self.service.clone(),
        }
    }
}

/// This is a Tower Layer which applies the OptionalMAuthValidationService on top of the
/// service provided to it.
#[derive(Clone)]
pub struct OptionalMAuthValidationLayer {
    config_info: ConfigFileSection,
}

impl<S> Layer<S> for OptionalMAuthValidationLayer {
    type Service = OptionalMAuthValidationService<S>;

    fn layer(&self, service: S) -> Self::Service {
        OptionalMAuthValidationService {
            // unwrap is safe because we validated the config_info before constructing the layer
            mauth_info: MAuthInfo::from_config_section(&self.config_info).unwrap(),
            config_info: self.config_info.clone(),
            service,
        }
    }
}

impl OptionalMAuthValidationLayer {
    /// Construct an OptionalMAuthValidationLayer based on the configuration options in the file
    /// found in the default location.
    pub fn from_default_file() -> Result<Self, ConfigReadError> {
        let config_info = MAuthInfo::config_section_from_default_file()?;
        // Generate a MAuthInfo and then drop it to validate that it works,
        // making it safe to use `unwrap` in the service constructor.
        MAuthInfo::from_config_section(&config_info)?;
        Ok(OptionalMAuthValidationLayer { config_info })
    }

    /// Construct an OptionalMAuthValidationLayer based on the configuration options in a manually
    /// created or parsed ConfigFileSection.
    pub fn from_config_section(config_info: ConfigFileSection) -> Result<Self, ConfigReadError> {
        MAuthInfo::from_config_section(&config_info)?;
        Ok(OptionalMAuthValidationLayer { config_info })
    }
}

impl<S> FromRequestParts<S> for ValidatedRequestDetails
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ValidatedRequestDetails>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

impl<S> OptionalFromRequestParts<S> for ValidatedRequestDetails
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<ValidatedRequestDetails>().cloned())
    }
}

impl<S> OptionalFromRequestParts<S> for MAuthValidationError
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<MAuthValidationError>().cloned())
    }
}
