# mauth-client

## mauth-client

This crate allows users of the Hyper crate for making HTTP requests to sign those requests with
the MAuth protocol, and verify the responses. Usage example:

**Note**: This crate and Rust support within Medidata is considered experimental. Do not
release any code to Production or deploy in a Client-accessible environment without getting
approval for the full stack used through the Architecture and Security groups.

```rust
let mauth_info = MAuthInfo::from_default_file().unwrap();
let client = Client::new();
let uri: Url = "https://www.example.com/".parse().unwrap();
let (body, body_digest) = MAuthInfo::build_body_with_digest("".to_string());
let mut req = Request::new(Method::GET, uri);
*req.body_mut() = Some(body);
mauth_info.sign_request(&mut req, &body_digest);
match client.execute(req).await {
    Err(err) => println!("Got error {}", err),
    Ok(response) => match mauth_info.validate_response(response).await {
        Ok(resp_body) => println!(
            "Got validated response with body {}",
            &String::from_utf8(resp_body).unwrap()
        ),
        Err(err) => println!("Error validating response: {:?}", err),
    }
}
```

The optional `axum-service` feature provides for a Tower Layer and Service that will
authenticate incoming requests via MAuth V2 or V1 and provide to the lower layers a
validated app_uuid from the request via the ValidatedRequestDetails struct.

License: MIT
