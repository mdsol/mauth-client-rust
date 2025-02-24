use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result};

use crate::{MAuthInfo, sign_outgoing::SigningError};

#[async_trait::async_trait]
impl Middleware for MAuthInfo {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        self.sign_request(&mut req)?;
        next.run(req, extensions).await
    }
}

impl From<SigningError> for reqwest_middleware::Error {
    fn from(value: SigningError) -> Self {
        reqwest_middleware::Error::Middleware(value.into())
    }
}
