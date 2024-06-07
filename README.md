# mauth-client

## mauth-client

This crate allows users of the Reqwest crate for making HTTP requests to sign those requests with
the MAuth protocol, and verify the responses. Usage example:

**Note**: This crate and Rust support within Medidata is considered experimental. Do not
release any code to Production or deploy in a Client-accessible environment without getting
approval for the full stack used through the Architecture and Security groups.

```rust
let mauth_info = MAuthInfo::from_default_file().unwrap();
let client = Client::new();
let uri: Url = "https://www.example.com/".parse().unwrap();
let mut req = Request::new(Method::GET, uri);
mauth_info.sign_request(&mut req, &[]);
match client.execute(req).await {
    Err(err) => println!("Got error {}", err),
    Ok(response) => println!("Got validated response with body {}", response.text().await.unwrap()),
}
```


The above code will read your mauth configuration from a file in `~/.mauth_config.yml` which format is:
```yaml
common: &common
  mauth_baseurl: https://<URL of MAUTH SERVER>
  mauth_api_version: v1
  app_uuid: <YOUR APP UUID HERE>
  private_key_file: <PATH TO MAUTH KEY>
```

The optional `axum-service` feature provides for a Tower Layer and Service that will
authenticate incoming requests via MAuth V2 or V1 and provide to the lower layers a
validated app_uuid from the request via the ValidatedRequestDetails struct.

License: MIT
