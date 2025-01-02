# mauth-client

This crate allows users of the Reqwest crate for making HTTP requests to sign those requests with
the MAuth protocol, and verify the responses. Usage example:

**Note**: This crate and Rust support within Medidata is considered experimental. Do not
release any code to Production or deploy in a Client-accessible environment without getting
approval for the full stack used through the Architecture and Security groups.

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

The optional `axum-service` feature provides for a Tower Layer and Service that will
authenticate incoming requests via MAuth V2 or V1 and provide to the lower layers a
validated app_uuid from the request via the ValidatedRequestDetails struct. Note that
this feature now includes a `RequiredMAuthValidationLayer`, which will reject any
requests without a valid signature before they reach lower layers, and also a
`OptionalMAuthValidationLayer`, which lets all requests through, but only attaches a
ValidatedRequestDetails extension struct if there is a valid signature. When using this
layer, it is the responsiblity of the request handler to check for the extension and
reject requests that are not properly authorized.

There are also optional features `tracing-otel-26` and `tracing-otel-27` that pair with
the `axum-service` feature to ensure that any outgoing requests for credentials that take
place in the context of an incoming web request also include the proper OpenTelemetry span
information in any requests to MAudit services. Note that it is critical to use the same
version of OpenTelemetry crates as the rest of the project - if you do not, there will be 2
or more instances of the OpenTelemetry global information, and requests may not be traced
through properly.
