# mauth-client-rust

## mauth-client-rust

This crate allows users of the Hyper crate for making HTTP requests to sign those requests with
the MAuth protocol, and verify the responses. Usage example:

```rust
let mauth_info = MAuthInfo::from_default_file().await.unwrap();
let https = HttpsConnector::new();
let client = Client::builder().build::<_, hyper::Body>(https);
let uri: hyper::Uri = "https://www.example.com/".parse().unwrap();
let (body, body_digest) = MAuthInfo::build_body_with_digest("".to_string());
let mut req = Request::new(body);
*req.method_mut() = Method::GET;
*req.uri_mut() = uri.clone();
mauth_info.sign_request_v2(&mut req, body_digest);
match client.request(req).await {
    Err(err) => println!("Got error {}", err),
    Ok(response) => match mauth_info.validate_response_v2(response).await {
        Ok(resp_body) => println!("Got validated response body {}", &resp_body),
        Err(err) => println!("Error validating response: {:?}", err),
    }
}
```
