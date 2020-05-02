use crate::{ConfigFileSection, MAuthInfo};
use hyper::{Method, Request};
use serde::Deserialize;
use tokio::fs;

use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct RequestShape {
    verb: String,
    url: String,
    body: Option<String>,
}

#[derive(Deserialize)]
struct TestSignConfig {
    app_uuid: String,
    request_time: u64,
    private_key_file: String,
}

const BASE_PATH: &'static str = "mauth-protocol-test-suite/protocols/MWSV2/";

async fn setup_mauth_info() -> (MAuthInfo, u64) {
    let config_path = Path::new("mauth-protocol-test-suite/signing-config.json");
    let sign_config: TestSignConfig =
        serde_json::from_slice(&fs::read(config_path).await.unwrap()).unwrap();
    let mock_config_section = ConfigFileSection {
        app_uuid: sign_config.app_uuid,
        mauth_baseurl: "https://www.example.com/".to_string(),
        mauth_api_version: "v1".to_string(),
        private_key_file: format!(
            "mauth-protocol-test-suite{}",
            sign_config.private_key_file.replace('.', "")
        ),
        v2_only_sign_requests: None,
        v2_only_authenticate: None,
    };
    (
        MAuthInfo::from_config_section(mock_config_section)
            .await
            .unwrap(),
        sign_config.request_time,
    )
}

#[tokio::test]
async fn get_vanilla_string_to_sign() {
    let (mauth_info, req_time) = setup_mauth_info().await;
    let mut req_file_path = PathBuf::from(&BASE_PATH);
    req_file_path.push("get-vanilla/get-vanilla.req");
    let request_shape: RequestShape =
        serde_json::from_slice(&fs::read(req_file_path).await.unwrap()).unwrap();

    let mut sts_file_path = PathBuf::from(&BASE_PATH);
    sts_file_path.push("get-vanilla/get-vanilla.sts");
    let expected_string_to_sign =
        String::from_utf8(fs::read(sts_file_path).await.unwrap()).unwrap();

    let (body, digest) =
        MAuthInfo::build_body_with_digest(request_shape.body.unwrap_or("".to_string()));
    let mut req = Request::new(body);
    *req.method_mut() = Method::from_bytes(request_shape.verb.as_bytes()).unwrap();
    *req.uri_mut() = request_shape.url.parse().unwrap();
    let sts = mauth_info.get_signing_string_v2(&req, &digest, &req_time.to_string());

    assert_eq!(expected_string_to_sign, sts);
}

#[tokio::test]
async fn get_vanilla_sign_string() {
    let (mauth_info, _) = setup_mauth_info().await;
    let mut sts_file_path = PathBuf::from(&BASE_PATH);
    sts_file_path.push("get-vanilla/get-vanilla.sts");
    let string_to_sign = String::from_utf8(fs::read(sts_file_path).await.unwrap()).unwrap();

    let mut sig_file_path = PathBuf::from(&BASE_PATH);
    sig_file_path.push("get-vanilla/get-vanilla.sig");
    let expected_sig = String::from_utf8(fs::read(sig_file_path).await.unwrap()).unwrap();

    let signed = mauth_info.sign_string_v2(string_to_sign);

    assert_eq!(expected_sig, signed);
}

#[tokio::test]
async fn get_vanilla_generate_headers() {
    let (mauth_info, req_time) = setup_mauth_info().await;

    let mut sig_file_path = PathBuf::from(&BASE_PATH);
    sig_file_path.push("get-vanilla/get-vanilla.sig");
    let sig = String::from_utf8(fs::read(sig_file_path).await.unwrap()).unwrap();

    let mut authz_file_path = PathBuf::from(&BASE_PATH);
    authz_file_path.push("get-vanilla/get-vanilla.authz");
    let auth_headers: serde_json::Value =
        serde_json::from_slice(&fs::read(authz_file_path).await.unwrap()).unwrap();

    let (body, _) = MAuthInfo::build_body_with_digest("".to_string());
    let mut request = Request::new(body);
    mauth_info.set_headers_v2(&mut request, sig, &req_time.to_string());

    let headers = request.headers();
    let time_header = headers.get("MCC-Time").unwrap().to_str().unwrap();
    let sig_header = headers.get("MCC-Authentication").unwrap().to_str().unwrap();

    let expected_time = auth_headers
        .get("MCC-Time")
        .unwrap()
        .as_u64()
        .unwrap()
        .to_string();
    let expected_sig = auth_headers
        .get("MCC-Authentication")
        .unwrap()
        .as_str()
        .unwrap();

    assert_eq!(expected_time, time_header);
    assert_eq!(expected_sig, sig_header);
}
