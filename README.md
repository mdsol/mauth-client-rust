# mauth-client

## mauth-client

This crate allows users of the Hyper crate for making HTTP requests to sign those requests with
the MAuth protocol, and verify the responses. Usage example:

**Note**: This crate and Rust support within Medidata is considered experimental. Do not
release any code to Production or deploy in a Client-accessible environment without getting
approval for the full stack used through the Architecture and Security groups.

```rust
let mauth_info = MAuthInfo::from_default_file().unwrap();
let https = HttpsConnector::new();
let client = Client::builder().build::<_, hyper::Body>(https);
let uri: hyper::Uri = "https://www.example.com/".parse().unwrap();
let (body, body_digest) = MAuthInfo::build_body_with_digest("".to_string());
let mut req = Request::new(body);
*req.method_mut() = Method::GET;
*req.uri_mut() = uri.clone();
mauth_info.sign_request(&mut req, &body_digest);
match client.request(req).await {
    Err(err) => println!("Got error {}", err),
    Ok(mut response) => match mauth_info.validate_response(&mut response).await {
        Ok(resp_body) => println!(
            "Got validated response with status {} and body {}",
            &response.status().as_str(),
            &String::from_utf8(resp_body).unwrap()
        ),
        Err(err) => println!("Error validating response: {:?}", err),
    }
}
```
