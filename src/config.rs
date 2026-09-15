use crate::{CLIENT, MAuthInfo};
use mauth_core::signer::Signer;
use reqwest::Client;
use reqwest::Url;
use reqwest_middleware::ClientBuilder;
use serde::Deserialize;
use std::io;
use thiserror::Error;
use uuid::Uuid;

const CONFIG_FILE: &str = ".mauth_config.yml";

impl MAuthInfo {
    /// Construct the MAuthInfo struct based on the contents of the config file `.mauth_config.yml`
    /// present in the current user's home directory. Returns an enum error type that includes the
    /// error types of all crates used.
    pub fn from_default_file() -> Result<MAuthInfo, ConfigReadError> {
        Self::from_config_section(&Self::config_section_from_default_file()?)
    }

    pub(crate) fn config_section_from_default_file() -> Result<ConfigFileSection, ConfigReadError> {
        let mut home = dirs::home_dir().unwrap();
        home.push(CONFIG_FILE);
        let config_data = std::fs::read_to_string(&home)?;
        Self::config_section_from_yaml(&config_data)
    }

    /// Parse the `common` section out of the YAML contents of a config file.
    pub(crate) fn config_section_from_yaml(
        config_data: &str,
    ) -> Result<ConfigFileSection, ConfigReadError> {
        let config_data_value: yaml_serde::Value = yaml_serde::from_str(config_data)?;
        let common_section = config_data_value
            .get("common")
            .ok_or(ConfigReadError::InvalidFile(None))?;
        let common_section_typed: ConfigFileSection =
            yaml_serde::from_value(common_section.clone())?;
        Ok(common_section_typed)
    }

    /// Construct the MAuthInfo struct based on a passed-in ConfigFileSection instance. The
    /// optional input_keystore is present to support internal cloning and need not be provided
    /// if being used outside of the crate.
    pub fn from_config_section(section: &ConfigFileSection) -> Result<MAuthInfo, ConfigReadError> {
        let full_uri: Url = format!(
            "{}/mauth/{}/security_tokens/",
            section.mauth_baseurl, section.mauth_api_version
        )
        .parse()?;

        let mut pk_data = section.private_key_data.clone();
        if pk_data.is_none()
            && let Some(pk_file_path) = section.private_key_file.as_ref()
        {
            pk_data = Some(std::fs::read_to_string(pk_file_path)?);
        }
        if pk_data.is_none() {
            return Err(ConfigReadError::NoPrivateKey);
        }

        let mauth_info = MAuthInfo {
            app_id: Uuid::parse_str(&section.app_uuid)?,
            mauth_uri_base: full_uri,
            sign_with_v1_also: !section.v2_only_sign_requests.unwrap_or(false),
            allow_v1_auth: !section.v2_only_authenticate.unwrap_or(false),
            signer: Signer::new(section.app_uuid.clone(), pk_data.unwrap())?,
        };

        #[cfg(feature = "axum-service")]
        crate::init_pubkey_cache(section.pubkey_cache_capacity);

        CLIENT.get_or_init(|| {
            let builder = ClientBuilder::new(Client::new()).with(mauth_info.clone());
            #[cfg(any(
                feature = "tracing-otel-26",
                feature = "tracing-otel-27",
                feature = "tracing-otel-28",
                feature = "tracing-otel-29",
                feature = "tracing-otel-30",
                feature = "tracing-otel-31",
                feature = "tracing-otel-32",
            ))]
            let builder = builder.with(reqwest_tracing::TracingMiddleware::default());
            builder.build()
        });

        Ok(mauth_info)
    }
}

/// All of the configuration data needed to set up a MAuthInfo struct. Implements Deserialize
/// to be read from a YAML file easily, or can be created manually.
#[derive(Deserialize, Clone)]
pub struct ConfigFileSection {
    pub app_uuid: String,
    pub mauth_baseurl: String,
    pub mauth_api_version: String,
    pub private_key_file: Option<String>,
    pub private_key_data: Option<String>,
    pub v2_only_sign_requests: Option<bool>,
    pub v2_only_authenticate: Option<bool>,
    /// How many verifying keys to retain when validating incoming requests.
    /// `None` uses a default sized for a wide-fanout service; raise it only if
    /// more distinct applications than that call this service within the
    /// lifetime MAuth puts on a key. Ignored without the `axum-service` feature.
    ///
    /// Only the first configuration loaded in a process takes effect.
    pub pubkey_cache_capacity: Option<usize>,
}

impl Default for ConfigFileSection {
    fn default() -> Self {
        Self {
            app_uuid: "".to_string(),
            mauth_baseurl: "".to_string(),
            mauth_api_version: "v1".to_string(),
            private_key_file: None,
            private_key_data: None,
            v2_only_sign_requests: Some(true),
            v2_only_authenticate: Some(true),
            pubkey_cache_capacity: None,
        }
    }
}

/// All of the possible errors that can take place when attempting to read a config file. Errors
/// are specific to the libraries that created them, and include the details from those libraries.
#[derive(Debug, Error)]
pub enum ConfigReadError {
    #[error("File Read Error: {0}")]
    FileReadError(#[from] io::Error),
    #[error("Not a valid maudit config file: {0:?}")]
    InvalidFile(Option<yaml_serde::Error>),
    #[error("MAudit URI not valid: {0}")]
    InvalidUri(#[from] url::ParseError),
    #[error("App UUID not valid: {0}")]
    InvalidAppUuid(#[from] uuid::Error),
    #[error("Unable to parse RSA private key: {0}")]
    PrivateKeyDecodeError(String),
    #[error("Neither private_key_file nor private_key_data were provided")]
    NoPrivateKey,
}

impl From<mauth_core::error::Error> for ConfigReadError {
    fn from(err: mauth_core::error::Error) -> ConfigReadError {
        match err {
            mauth_core::error::Error::PrivateKeyDecodeError(pkey_err) => {
                ConfigReadError::PrivateKeyDecodeError(format!("{pkey_err}"))
            }
            _ => panic!("should not be possible to get this error type from signer construction"),
        }
    }
}

impl From<yaml_serde::Error> for ConfigReadError {
    fn from(err: yaml_serde::Error) -> ConfigReadError {
        ConfigReadError::InvalidFile(Some(err))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::fs;

    #[test]
    fn parses_documented_common_section() {
        let yaml = "\
common: &common
  mauth_baseurl: https://mauth.example.com
  mauth_api_version: v1
  app_uuid: c7db7fde-2448-11ef-b358-125eb8485a60
  private_key_file: /path/to/key.pem
";
        let section = MAuthInfo::config_section_from_yaml(yaml).unwrap();
        assert_eq!(section.mauth_baseurl, "https://mauth.example.com");
        assert_eq!(section.mauth_api_version, "v1");
        assert_eq!(section.app_uuid, "c7db7fde-2448-11ef-b358-125eb8485a60");
        assert_eq!(
            section.private_key_file.as_deref(),
            Some("/path/to/key.pem")
        );
        assert!(section.private_key_data.is_none());
        assert!(section.v2_only_sign_requests.is_none());
        assert!(section.v2_only_authenticate.is_none());
        assert!(section.pubkey_cache_capacity.is_none());
    }

    #[test]
    fn parses_optional_fields_and_ignores_other_sections() {
        let yaml = "\
common: &common
  mauth_baseurl: https://mauth.example.com
  mauth_api_version: v1
  app_uuid: c7db7fde-2448-11ef-b358-125eb8485a60
  private_key_data: |
    -----BEGIN RSA PRIVATE KEY-----
    not-really-a-key
    -----END RSA PRIVATE KEY-----
  v2_only_sign_requests: true
  v2_only_authenticate: false
  pubkey_cache_capacity: 42
development:
  <<: *common
  mauth_baseurl: https://mauth-dev.example.com
";
        let section = MAuthInfo::config_section_from_yaml(yaml).unwrap();
        assert_eq!(section.mauth_baseurl, "https://mauth.example.com");
        assert!(section.private_key_file.is_none());
        let key = section.private_key_data.unwrap();
        assert!(key.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(key.contains("not-really-a-key"));
        assert_eq!(section.v2_only_sign_requests, Some(true));
        assert_eq!(section.v2_only_authenticate, Some(false));
        assert_eq!(section.pubkey_cache_capacity, Some(42));
    }

    #[test]
    fn missing_common_section_returns_right_error() {
        let yaml = "\
development:
  mauth_baseurl: https://mauth.example.com
  mauth_api_version: v1
  app_uuid: c7db7fde-2448-11ef-b358-125eb8485a60
";
        let result = MAuthInfo::config_section_from_yaml(yaml);
        assert!(matches!(result, Err(ConfigReadError::InvalidFile(None))));
    }

    #[test]
    fn missing_required_field_returns_right_error() {
        let yaml = "\
common:
  mauth_baseurl: https://mauth.example.com
  mauth_api_version: v1
";
        let result = MAuthInfo::config_section_from_yaml(yaml);
        assert!(matches!(result, Err(ConfigReadError::InvalidFile(Some(_)))));
    }

    #[test]
    fn malformed_yaml_returns_right_error() {
        let result = MAuthInfo::config_section_from_yaml("common: [unterminated");
        assert!(matches!(result, Err(ConfigReadError::InvalidFile(Some(_)))));
    }

    #[tokio::test]
    async fn invalid_uri_returns_right_error() {
        let bad_config = ConfigFileSection {
            app_uuid: "".to_string(),
            mauth_baseurl: "dfaedfaewrfaew".to_string(),
            mauth_api_version: "".to_string(),
            private_key_file: Some("".to_string()),
            private_key_data: None,
            v2_only_sign_requests: None,
            v2_only_authenticate: None,
            pubkey_cache_capacity: None,
        };
        let load_result = MAuthInfo::from_config_section(&bad_config);
        assert!(matches!(load_result, Err(ConfigReadError::InvalidUri(_))));
    }

    #[tokio::test]
    async fn bad_file_path_returns_right_error() {
        let bad_config = ConfigFileSection {
            app_uuid: "".to_string(),
            mauth_baseurl: "https://example.com/".to_string(),
            mauth_api_version: "v1".to_string(),
            private_key_file: Some("no_such_file".to_string()),
            private_key_data: None,
            v2_only_sign_requests: None,
            v2_only_authenticate: None,
            pubkey_cache_capacity: None,
        };
        let load_result = MAuthInfo::from_config_section(&bad_config);
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
            app_uuid: "c7db7fde-2448-11ef-b358-125eb8485a60".to_string(),
            mauth_baseurl: "https://example.com/".to_string(),
            mauth_api_version: "v1".to_string(),
            private_key_file: Some(filename.to_string()),
            private_key_data: None,
            v2_only_sign_requests: None,
            v2_only_authenticate: None,
            pubkey_cache_capacity: None,
        };
        let load_result = MAuthInfo::from_config_section(&bad_config);
        fs::remove_file(&filename).await.unwrap();
        assert!(matches!(
            load_result,
            Err(ConfigReadError::PrivateKeyDecodeError(_))
        ));
    }

    #[tokio::test]
    async fn bad_uuid_returns_right_error() {
        let filename = "valid_key_file";
        fs::write(&filename, "invalid data").await.unwrap();
        let bad_config = ConfigFileSection {
            app_uuid: "".to_string(),
            mauth_baseurl: "https://example.com/".to_string(),
            mauth_api_version: "v1".to_string(),
            private_key_file: Some(filename.to_string()),
            private_key_data: None,
            v2_only_sign_requests: None,
            v2_only_authenticate: None,
            pubkey_cache_capacity: None,
        };
        let load_result = MAuthInfo::from_config_section(&bad_config);
        fs::remove_file(&filename).await.unwrap();
        assert!(matches!(
            load_result,
            Err(ConfigReadError::InvalidAppUuid(_))
        ));
    }
}
