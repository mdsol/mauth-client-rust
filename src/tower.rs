use futures_core::future::BoxFuture;
use hyper::{body::Body, Request};
use openssl::{pkey::Public, rsa::Rsa};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tower::{Layer, Service};
use uuid::Uuid;

use crate::{ConfigFileSection, ConfigReadError, MAuthInfo};

pub struct MAuthValidationService<S> {
    mauth_info: MAuthInfo,
    config_info: ConfigFileSection,
    service: S,
}

impl<S> Service<Request<Body>> for MAuthValidationService<S>
where
    S: Service<Request<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn Error + Sync + Send>>,
{
    type Response = S::Response;
    type Error = Box<dyn Error + Sync + Send>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(|e| e.into())
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
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
            mauth_info: MAuthInfo::from_config_section(
                &self.config_info,
                Some(self.mauth_info.remote_key_store.clone()),
            )
            .unwrap(),
            config_info: self.config_info.clone(),
            service: self.service.clone(),
        }
    }
}

#[derive(Clone)]
pub struct MAuthValidationLayer {
    config_info: ConfigFileSection,
    remote_key_store: Arc<RwLock<HashMap<Uuid, Rsa<Public>>>>,
}

impl<S> Layer<S> for MAuthValidationLayer {
    type Service = MAuthValidationService<S>;

    fn layer(&self, service: S) -> Self::Service {
        MAuthValidationService {
            // unwrap is safe because we validated the config_info before constructing the layer
            mauth_info: MAuthInfo::from_config_section(
                &self.config_info,
                Some(self.remote_key_store.clone()),
            )
            .unwrap(),
            config_info: self.config_info.clone(),
            service,
        }
    }
}

impl MAuthValidationLayer {
    pub fn from_default_file() -> Result<Self, ConfigReadError> {
        let config_info = MAuthInfo::config_section_from_default_file()?;
        let remote_key_store = Arc::new(RwLock::new(HashMap::new()));
        // Generate a MAuthInfo and then drop it to validate that it works,
        // making it safe to use `unwrap` in the service constructor.
        MAuthInfo::from_config_section(&config_info, Some(remote_key_store.clone()))?;
        Ok(MAuthValidationLayer {
            config_info,
            remote_key_store,
        })
    }
}
