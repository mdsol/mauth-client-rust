use crate::{ConfigFileSection, ConfigReadError, MAuthInfo};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use tokio::fs;

#[tokio::test]
async fn invalid_uri_returns_right_error() {
    let bad_config = ConfigFileSection {
        app_uuid: "".to_string(),
        mauth_baseurl: "dfaedfaewrfaew".to_string(),
        mauth_api_version: "".to_string(),
        private_key_file: "".to_string(),
        v2_only_sign_requests: None,
        v2_only_authenticate: None,
    };
    let load_result = MAuthInfo::from_config_section(&bad_config, None);
    assert!(matches!(load_result, Err(ConfigReadError::InvalidUri(_))));
}

#[tokio::test]
async fn bad_file_path_returns_right_error() {
    let bad_config = ConfigFileSection {
        app_uuid: "".to_string(),
        mauth_baseurl: "https://example.com/".to_string(),
        mauth_api_version: "v1".to_string(),
        private_key_file: "no_such_file".to_string(),
        v2_only_sign_requests: None,
        v2_only_authenticate: None,
    };
    let load_result = MAuthInfo::from_config_section(&bad_config, None);
    assert!(matches!(
        load_result,
        Err(ConfigReadError::FileReadError(_))
    ));
}

#[tokio::test]
async fn bad_key_file_returns_right_error() {
    let filename = "dummy_file";
    fs::write(&filename, b"definitely not a key").await.unwrap();
    let bad_config = ConfigFileSection {
        app_uuid: "".to_string(),
        mauth_baseurl: "https://example.com/".to_string(),
        mauth_api_version: "v1".to_string(),
        private_key_file: filename.to_string(),
        v2_only_sign_requests: None,
        v2_only_authenticate: None,
    };
    let load_result = MAuthInfo::from_config_section(&bad_config, None);
    fs::remove_file(&filename).await.unwrap();
    assert!(matches!(load_result, Err(ConfigReadError::OpenSSLError(_))));
}

#[tokio::test]
async fn bad_uuid_returns_right_error() {
    let filename = "valid_key_file";
    let rsa_obj = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    fs::write(&filename, rsa_obj.private_key_to_pem_pkcs8().unwrap())
        .await
        .unwrap();
    let bad_config = ConfigFileSection {
        app_uuid: "".to_string(),
        mauth_baseurl: "https://example.com/".to_string(),
        mauth_api_version: "v1".to_string(),
        private_key_file: filename.to_string(),
        v2_only_sign_requests: None,
        v2_only_authenticate: None,
    };
    let load_result = MAuthInfo::from_config_section(&bad_config, None);
    fs::remove_file(&filename).await.unwrap();
    assert!(matches!(
        load_result,
        Err(ConfigReadError::InvalidAppUuid(_))
    ));
}
