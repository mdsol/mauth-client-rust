//! Structs and impls related to providing a Tower Service and Layer to verify incoming requests

use axum::extract::Request;
use futures_core::future::BoxFuture;
use std::error::Error;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use crate::{
    config::{ConfigFileSection, ConfigReadError},
    MAuthInfo,
};

/// This is a Tower Service which validates that incoming requests have a valid
/// MAuth signature. It only passes the request down to the next layer if the
/// signature is valid, otherwise it returns an appropriate error to the caller.
pub struct MAuthValidationService<S> {
    mauth_info: MAuthInfo,
    config_info: ConfigFileSection,
    service: S,
}

impl<S> Service<Request> for MAuthValidationService<S>
where
    S: Service<Request> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn Error + Sync + Send>>,
{
    type Response = S::Response;
    type Error = Box<dyn Error + Sync + Send>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(|e| e.into())
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let mut cloned = self.clone();
        Box::pin(async move {
            match cloned.mauth_info.validate_request(request).await {
                Ok(valid_request) => match cloned.service.call(valid_request).await {
                    Ok(response) => Ok(response),
                    Err(err) => Err(err.into()),
                },
                Err(err) => Err(Box::new(err) as Box<dyn Error + Send + Sync>),
            }
        })
    }
}

impl<S: Clone> Clone for MAuthValidationService<S> {
    fn clone(&self) -> Self {
        MAuthValidationService {
            // unwrap is safe because we validated the config_info before constructing the layer
            mauth_info: MAuthInfo::from_config_section(&self.config_info).unwrap(),
            config_info: self.config_info.clone(),
            service: self.service.clone(),
        }
    }
}

/// This is a Tower Layer which applies the MAuthValidationService on top of the
/// service provided to it.
#[derive(Clone)]
pub struct MAuthValidationLayer {
    config_info: ConfigFileSection,
}

impl<S> Layer<S> for MAuthValidationLayer {
    type Service = MAuthValidationService<S>;

    fn layer(&self, service: S) -> Self::Service {
        MAuthValidationService {
            // unwrap is safe because we validated the config_info before constructing the layer
            mauth_info: MAuthInfo::from_config_section(&self.config_info).unwrap(),
            config_info: self.config_info.clone(),
            service,
        }
    }
}

impl MAuthValidationLayer {
    /// Construct a MAuthValidationLayer based on the configuration options in the file
    /// found in the default location.
    pub fn from_default_file() -> Result<Self, ConfigReadError> {
        let config_info = MAuthInfo::config_section_from_default_file()?;
        // Generate a MAuthInfo and then drop it to validate that it works,
        // making it safe to use `unwrap` in the service constructor.
        MAuthInfo::from_config_section(&config_info)?;
        Ok(MAuthValidationLayer { config_info })
    }

    /// Construct a MAuthValidationLayer based on the configuration options in a manually
    /// created or parsed ConfigFileSection.
    pub fn from_config_section(config_info: ConfigFileSection) -> Result<Self, ConfigReadError> {
        MAuthInfo::from_config_section(&config_info)?;
        Ok(MAuthValidationLayer { config_info })
    }
}
