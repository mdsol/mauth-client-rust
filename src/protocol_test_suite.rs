use crate::{MAuthInfo, config::ConfigFileSection};
use mauth_core::verifier::Verifier;
use reqwest::{Method, Request};
use serde::Deserialize;
use tokio::fs;

use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct TestSignConfig {
    app_uuid: String,
    request_time: u64,
    private_key_file: String,
}

const BASE_PATH: &str = "mauth-protocol-test-suite/protocols/MWSV2/";

async fn setup_mauth_info() -> (MAuthInfo, String, u64) {
    let config_path = Path::new("mauth-protocol-test-suite/signing-config.json");
    let sign_config: TestSignConfig =
        serde_json::from_slice(&fs::read(config_path).await.unwrap()).unwrap();
    let app_uuid = sign_config.app_uuid.clone();
    let mock_config_section = ConfigFileSection {
        app_uuid: sign_config.app_uuid,
        mauth_baseurl: "https://www.example.com/".to_string(),
        mauth_api_version: "v1".to_string(),
        private_key_file: Some(format!(
            "mauth-protocol-test-suite{}",
            sign_config.private_key_file.replace('.', "")
        )),
        private_key_data: None,
        v2_only_sign_requests: None,
        v2_only_authenticate: None,
    };
    (
        MAuthInfo::from_config_section(&mock_config_section).unwrap(),
        app_uuid,
        sign_config.request_time,
    )
}

async fn test_generate_headers(file_name: String) {
    let (mauth_info, _, req_time) = setup_mauth_info().await;

    let mut sig_file_path = PathBuf::from(&BASE_PATH);
    sig_file_path.push(format!("{name}/{name}.sig", name = &file_name));
    let sig = String::from_utf8(fs::read(sig_file_path).await.unwrap()).unwrap();

    let mut authz_file_path = PathBuf::from(&BASE_PATH);
    authz_file_path.push(format!("{name}/{name}.authz", name = &file_name));
    let auth_headers: serde_json::Value =
        serde_json::from_slice(&fs::read(authz_file_path).await.unwrap()).unwrap();

    let mut request = Request::new(Method::GET, url::Url::parse("http://www.a.com/").unwrap());
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

#[tokio::test]
async fn sign_request_v1_sets_protocol_compliant_headers() {
    let (mauth_info, app_uuid, _) = setup_mauth_info().await;
    let mut request = Request::new(Method::GET, url::Url::parse("http://www.a.com/").unwrap());
    mauth_info.sign_request_v1(&mut request).unwrap();

    let headers = request.headers();
    let timestamp = headers.get("X-MWS-Time").unwrap().to_str().unwrap();
    let auth_header = headers
        .get("X-MWS-Authentication")
        .unwrap()
        .to_str()
        .unwrap();
    let signature = auth_header
        .strip_prefix(&format!("MWS {app_uuid}:"))
        .expect("v1 authentication header must contain its protocol token and app UUID");
    assert!(!signature.is_empty());

    let public_key = fs::read_to_string("mauth-protocol-test-suite/signing-params/rsa-key-pub")
        .await
        .unwrap();
    Verifier::new(app_uuid, public_key)
        .unwrap()
        .verify_signature(
            1,
            request.method().as_str(),
            request.url().path(),
            request.url().query().unwrap_or(""),
            &[],
            timestamp,
            signature,
        )
        .unwrap();
}

include!(concat!(env!("OUT_DIR"), "/protocol_tests.rs"));
