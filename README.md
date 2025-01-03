# mauth-client

This crate allows users of the Reqwest crate for making HTTP requests to sign those requests with
the MAuth protocol, and verify the responses. Usage example:

**Note**: This crate and Rust support within Medidata is considered experimental. Do not
release any code to Production or deploy in a Client-accessible environment without getting
approval for the full stack used through the Architecture and Security groups.

## Outgoing Requests

```no_run
use mauth_client::MAuthInfo;
use reqwest::Client;
# async fn send_request() {
let mauth_info = MAuthInfo::from_default_file().unwrap();
let client = Client::new();
let mut req = client.get("https://www.example.com/").build().unwrap();
mauth_info.sign_request(&mut req);
match client.execute(req).await {
    Err(err) => println!("Got error {}", err),
    Ok(response) => println!("Got validated response with body {}", response.text().await.unwrap()),
}
# }
```

The above code will read your mauth configuration from a file in `~/.mauth_config.yml` which format is:
```yaml
common: &common
  mauth_baseurl: https://<URL of MAUTH SERVER>
  mauth_api_version: v1
  app_uuid: <YOUR APP UUID HERE>
  private_key_file: <PATH TO MAUTH KEY>
```

The `MAuthInfo` struct also functions as a outgoing middleware using the
[`reqwest-middleware`](https://crates.io/crates/reqwest-middleware) crate for a simpler API and easier
integration with other outgoing middleware:

```no_run
use mauth_client::MAuthInfo;
use reqwest::Client;
use reqwest_middleware::ClientBuilder;
# async fn send_request() {
let mauth_info = MAuthInfo::from_default_file().unwrap();
let client = ClientBuilder::new(Client::new()).with(mauth_info).build();
match client.get("https://www.example.com/").send().await {
    Err(err) => println!("Got error {}", err),
    Ok(response) => println!("Got validated response with body {}", response.text().await.unwrap()),
}
# }
```

## Incoming Requests

The optional `axum-service` feature provides for a Tower Layer and Service that will
authenticate incoming requests via MAuth V2 or V1 and provide to the lower layers a
validated app_uuid from the request via the `ValidatedRequestDetails` struct. Note that
this feature now includes a `RequiredMAuthValidationLayer`, which will reject any
requests without a valid signature before they reach lower layers, and also a
`OptionalMAuthValidationLayer`, which lets all requests through, but only attaches a
`ValidatedRequestDetails` extension struct if there is a valid signature. When using this
layer, it is the responsiblity of the request handler to check for the extension and
reject requests that are not properly authorized.

Note that `ValidatedRequestDetails` implements Axum's `FromRequestParts`, so you can
specify it bare in a request handler. This implementation includes returning a 401
Unauthorized status code if the extension is not present. If you would like to return
a different response, or respond to the lack of the extension in another way, you can
use a more manual mechanism to check for the extension and decide how to proceed if it
is not present.

### Examples for `RequiredMAuthValidationLayer`

```no_run
# async fn run_server() {
use mauth_client::{
    axum_service::RequiredMAuthValidationLayer,
    validate_incoming::ValidatedRequestDetails,
};
use axum::{http::StatusCode, Router, routing::get, serve};
use tokio::net::TcpListener;

// If there is not a valid mauth signature, this function will never run at all, and
// the request will return an empty 401 Unauthorized
async fn foo() -> StatusCode {
    StatusCode::OK
}

// In addition to returning a 401 Unauthorized without running if there is not a valid
// MAuth signature, this also makes the validated requesting app UUID available to
// the function
async fn bar(details: ValidatedRequestDetails) -> StatusCode {
    println!("Got a request from app with UUID: {}", details.app_uuid);
    StatusCode::OK
}

// This function will run regardless of whether or not there is a mauth signature
async fn baz() -> StatusCode {
    StatusCode::OK
}

// Attaching the baz route handler after the layer means the layer is not run for
// requests to that path, so no mauth checking will be performed for that route and
// any other routes attached after the layer
let router = Router::new()
    .route("/foo", get(foo))
    .route("/bar", get(bar))
    .layer(RequiredMAuthValidationLayer::from_default_file().unwrap())
    .route("/baz", get(baz));
let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
serve(listener, router).await.unwrap();
# }
```

### Examples for `OptionalMAuthValidationLayer`

```no_run
# async fn run_server() {
use mauth_client::{
    axum_service::OptionalMAuthValidationLayer,
    validate_incoming::ValidatedRequestDetails,
};
use axum::{http::StatusCode, Router, routing::get, serve};
use tokio::net::TcpListener;

// This request will run no matter what the authorization status is
async fn foo() -> StatusCode {
    StatusCode::OK
}

// If there is not a valid mauth signature, this function will never run at all, and
// the request will return an empty 401 Unauthorized
async fn bar(_: ValidatedRequestDetails) -> StatusCode {
    StatusCode::OK
}

// In addition to returning a 401 Unauthorized without running if there is not a valid
// MAuth signature, this also makes the validated requesting app UUID available to
// the function
async fn baz(details: ValidatedRequestDetails) -> StatusCode {
    println!("Got a request from app with UUID: {}", details.app_uuid);
    StatusCode::OK
}

// This request will run whether or not there is a valid mauth signature, but the Option
// provided can be used to tell you whether there was a valid signature, so you can
// implement things like multiple possible types of authentication or behavior other than
// a 401 return if there is no authentication
async fn bam(optional_details: Option<ValidatedRequestDetails>) -> StatusCode {
    match optional_details {
        Some(details) => println!("Got a request from app with UUID: {}", details.app_uuid),
        None => println!("Got a request without a valid mauth signature"),
    }
    StatusCode::OK
}

let router = Router::new()
    .route("/foo", get(foo))
    .route("/bar", get(bar))
    .route("/baz", get(baz))
    .route("/bam", get(bam))
    .layer(OptionalMAuthValidationLayer::from_default_file().unwrap());
let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
serve(listener, router).await.unwrap();
# }
```

### OpenTelemetry Integration

There are also optional features `tracing-otel-26` and `tracing-otel-27` that pair with
the `axum-service` feature to ensure that any outgoing requests for credentials that take
place in the context of an incoming web request also include the proper OpenTelemetry span
information in any requests to MAudit services. Note that it is critical to use the same
version of OpenTelemetry crates as the rest of the project - if you do not, there will be 2
or more instances of the OpenTelemetry global information, and requests may not be traced
through properly.
