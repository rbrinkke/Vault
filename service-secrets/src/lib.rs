use async_trait::async_trait;
use rvstruct::ValueStruct;
pub use secrecy::{ExposeSecret, SecretString};
use secret_vault::{
    errors::{
        SecretVaultDataNotFoundError, SecretVaultError, SecretVaultErrorPublicGenericDetails,
        SecretsSourceError,
    },
    ring_encryption::SecretVaultRingAeadEncryption,
    Secret, SecretMetadata, SecretName, SecretVaultBuilder, SecretVaultRef, SecretVaultResult,
    SecretVaultView, SecretsSource,
};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub struct SecretSpec {
    pub key: &'static str,
    pub required: bool,
    pub allow_plain_env_in_prod: bool,
    pub file_env_var: Option<&'static str>,
}

impl SecretSpec {
    pub const fn required(key: &'static str) -> Self {
        Self {
            key,
            required: true,
            allow_plain_env_in_prod: false,
            file_env_var: None,
        }
    }

    pub const fn optional(key: &'static str) -> Self {
        Self {
            key,
            required: false,
            allow_plain_env_in_prod: false,
            file_env_var: None,
        }
    }

    pub const fn allow_plain_env_in_prod(mut self) -> Self {
        self.allow_plain_env_in_prod = true;
        self
    }

    pub const fn with_file_env_var(mut self, file_env_var: &'static str) -> Self {
        self.file_env_var = Some(file_env_var);
        self
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RuntimeMode {
    Production,
    NonProduction,
}

impl RuntimeMode {
    fn from_app_env(app_env: &str) -> Self {
        if app_env.eq_ignore_ascii_case("production") {
            Self::Production
        } else {
            Self::NonProduction
        }
    }

    fn plain_env_allowed(self, spec: SecretSpec) -> bool {
        self == Self::NonProduction || spec.allow_plain_env_in_prod
    }
}

#[derive(Debug, Error)]
pub enum ServiceSecretsError {
    #[error("secret backend error: {0}")]
    Vault(#[from] SecretVaultError),
    #[error("unknown secret key: {0}")]
    UnknownKey(String),
    #[error("secret {key} is not valid UTF-8: {source}")]
    InvalidUtf8 {
        key: String,
        #[source]
        source: std::string::FromUtf8Error,
    },
}

struct RuntimeSource {
    specs: HashMap<String, SecretSpec>,
    mode: RuntimeMode,
    systemd_credentials_directory: Option<PathBuf>,
}

impl RuntimeSource {
    fn new(specs: &[SecretSpec], app_env: &str) -> Self {
        Self {
            specs: specs
                .iter()
                .map(|spec| (spec.key.to_string(), *spec))
                .collect(),
            mode: RuntimeMode::from_app_env(app_env),
            systemd_credentials_directory: std::env::var_os("CREDENTIALS_DIRECTORY")
                .or_else(|| std::env::var_os("SYSTEMD_CREDENTIALS_DIRECTORY"))
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
        }
    }

    fn resolve_file_path(&self, spec: SecretSpec) -> Option<PathBuf> {
        let file_env_var = spec
            .file_env_var
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}_FILE", spec.key));
        if let Some(path) = std::env::var_os(&file_env_var).filter(|value| !value.is_empty()) {
            return Some(PathBuf::from(path));
        }
        self.systemd_credentials_directory
            .as_ref()
            .map(|dir| dir.join(spec.key))
            .filter(|path| path.is_file())
    }

    fn read_secret_file(path: &Path) -> SecretVaultResult<Vec<u8>> {
        std::fs::read(path).map_err(|err| {
            SecretVaultError::DataNotFoundError(SecretVaultDataNotFoundError::new(
                SecretVaultErrorPublicGenericDetails::new("SECRET_FILE_NOT_FOUND".into()),
                format!("secret file {} is not readable: {}", path.display(), err),
            ))
        })
    }

    fn resolve_env_var(spec: SecretSpec) -> Option<OsString> {
        std::env::var_os(spec.key)
            .or_else(|| std::env::var_os(spec.key.to_uppercase()))
            .filter(|value| !value.is_empty())
    }
}

#[async_trait]
impl SecretsSource for RuntimeSource {
    fn name(&self) -> String {
        "RuntimeSource".to_string()
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map = HashMap::new();

        for secret_ref in references {
            let secret_key = secret_ref.key.secret_name.value().to_string();
            let spec = self.specs.get(&secret_key).copied().ok_or_else(|| {
                SecretVaultError::SecretsSourceError(SecretsSourceError::new(
                    SecretVaultErrorPublicGenericDetails::new("UNKNOWN_SECRET".into()),
                    format!("secret spec {} is not registered", secret_key),
                ))
            })?;

            let maybe_secret = if let Some(path) = self.resolve_file_path(spec) {
                Some(Self::read_secret_file(&path)?)
            } else if self.mode.plain_env_allowed(spec) {
                Self::resolve_env_var(spec)
                    .map(|value| value.to_string_lossy().into_owned().into_bytes())
            } else {
                None
            };

            match maybe_secret {
                Some(secret_value) => {
                    result_map.insert(
                        secret_ref.clone(),
                        Secret::new(
                            secret_value.into(),
                            SecretMetadata::create_from_ref(secret_ref),
                        ),
                    );
                }
                None if spec.required => {
                    return Err(SecretVaultError::DataNotFoundError(
                        SecretVaultDataNotFoundError::new(
                            SecretVaultErrorPublicGenericDetails::new("SECRET_NOT_FOUND".into()),
                            format!(
                                "secret {} not found in *_FILE path, systemd credentials directory, or allowed plain env",
                                spec.key
                            ),
                        ),
                    ));
                }
                None => {}
            }
        }

        Ok(result_map)
    }
}

type RuntimeVault = secret_vault::SecretVault<RuntimeSource, SecretVaultRingAeadEncryption>;

pub struct LoadedSecrets {
    vault: RuntimeVault,
    refs: HashMap<String, SecretVaultRef>,
}

impl LoadedSecrets {
    pub async fn load(specs: &[SecretSpec], app_env: &str) -> Result<Self, ServiceSecretsError> {
        let refs: Vec<SecretVaultRef> = specs
            .iter()
            .map(|spec| {
                SecretVaultRef::new(SecretName::from(spec.key.to_string()))
                    .with_required(spec.required)
            })
            .collect();
        let refs_by_key = refs
            .iter()
            .map(|secret_ref| {
                (
                    secret_ref.key.secret_name.value().to_string(),
                    secret_ref.clone(),
                )
            })
            .collect();

        let vault = SecretVaultBuilder::with_source(RuntimeSource::new(specs, app_env))
            .with_encryption(SecretVaultRingAeadEncryption::new()?)
            .with_secret_refs(refs.iter().collect())
            .build()?;
        vault.refresh().await?;

        Ok(Self {
            vault,
            refs: refs_by_key,
        })
    }

    async fn get_secret(&self, key: &str) -> Result<Option<Secret>, ServiceSecretsError> {
        let secret_ref = self
            .refs
            .get(key)
            .ok_or_else(|| ServiceSecretsError::UnknownKey(key.to_string()))?;
        Ok(self.vault.get_secret_by_ref(secret_ref).await?)
    }

    async fn require_secret(&self, key: &str) -> Result<Secret, ServiceSecretsError> {
        let secret_ref = self
            .refs
            .get(key)
            .ok_or_else(|| ServiceSecretsError::UnknownKey(key.to_string()))?;
        Ok(self.vault.require_secret_by_ref(secret_ref).await?)
    }

    pub async fn require_plain_string(&self, key: &str) -> Result<String, ServiceSecretsError> {
        Self::secret_to_string(key, self.require_secret(key).await?)
    }

    pub async fn optional_plain_string(
        &self,
        key: &str,
    ) -> Result<Option<String>, ServiceSecretsError> {
        self.get_secret(key)
            .await?
            .map(|secret| Self::secret_to_string(key, secret))
            .transpose()
    }

    pub async fn require_secret_string(
        &self,
        key: &str,
    ) -> Result<SecretString, ServiceSecretsError> {
        Ok(SecretString::new(
            self.require_plain_string(key).await?.into(),
        ))
    }

    pub async fn optional_secret_string(
        &self,
        key: &str,
    ) -> Result<Option<SecretString>, ServiceSecretsError> {
        Ok(self
            .optional_plain_string(key)
            .await?
            .map(|value| SecretString::new(value.into())))
    }

    fn secret_to_string(key: &str, secret: Secret) -> Result<String, ServiceSecretsError> {
        String::from_utf8(secret.value.ref_sensitive_value().clone()).map_err(|source| {
            ServiceSecretsError::InvalidUtf8 {
                key: key.to_string(),
                source,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn set_systemd_credentials_directory(path: &Path) {
        std::env::set_var("SYSTEMD_CREDENTIALS_DIRECTORY", path);
    }

    fn clear_runtime_vars(keys: &[&str]) {
        std::env::remove_var("SYSTEMD_CREDENTIALS_DIRECTORY");
        for key in keys {
            std::env::remove_var(key);
            std::env::remove_var(format!("{}_FILE", key));
        }
    }

    #[tokio::test]
    async fn loads_secret_from_file_env_var_in_production() {
        let dir = TempDir::new().unwrap();
        let secret_path = dir.path().join("DATABASE_URL");
        std::fs::write(&secret_path, "postgres://prod").unwrap();
        std::env::set_var("DATABASE_URL_FILE", &secret_path);

        let secrets = LoadedSecrets::load(&[SecretSpec::required("DATABASE_URL")], "production")
            .await
            .unwrap();
        assert_eq!(
            secrets.require_plain_string("DATABASE_URL").await.unwrap(),
            "postgres://prod"
        );

        std::env::remove_var("DATABASE_URL_FILE");
    }

    #[tokio::test]
    async fn file_env_var_takes_precedence_over_systemd_credentials_directory() {
        let file_dir = TempDir::new().unwrap();
        let systemd_dir = TempDir::new().unwrap();
        let file_path = file_dir.path().join("SERVICE_TOKEN");
        let systemd_path = systemd_dir.path().join("SERVICE_TOKEN");

        std::fs::write(&file_path, "file-token").unwrap();
        std::fs::write(&systemd_path, "dir-token").unwrap();

        std::env::set_var("SERVICE_TOKEN_FILE", &file_path);
        set_systemd_credentials_directory(systemd_dir.path());

        let secrets = LoadedSecrets::load(&[SecretSpec::required("SERVICE_TOKEN")], "production")
            .await
            .unwrap();
        assert_eq!(
            secrets.require_plain_string("SERVICE_TOKEN").await.unwrap(),
            "file-token"
        );

        clear_runtime_vars(&["SERVICE_TOKEN"]);
    }

    #[tokio::test]
    async fn loads_secret_from_systemd_credentials_directory_in_production() {
        let dir = TempDir::new().unwrap();
        let secret_path = dir.path().join("POSTGRES_URL");
        std::fs::write(&secret_path, "postgres://from-systemd").unwrap();
        set_systemd_credentials_directory(dir.path());

        let secrets = LoadedSecrets::load(&[SecretSpec::required("POSTGRES_URL")], "production")
            .await
            .unwrap();
        assert_eq!(
            secrets.require_plain_string("POSTGRES_URL").await.unwrap(),
            "postgres://from-systemd"
        );

        clear_runtime_vars(&["POSTGRES_URL"]);
    }

    #[tokio::test]
    async fn rejects_plain_env_in_production_by_default() {
        std::env::set_var("PROD_ONLY_SECRET", "plain-prod");

        let err =
            match LoadedSecrets::load(&[SecretSpec::required("PROD_ONLY_SECRET")], "production")
                .await
            {
                Ok(_) => panic!("production plain env secret should not load"),
                Err(err) => err,
            };
        assert!(err.to_string().contains("Data not found"));

        std::env::remove_var("PROD_ONLY_SECRET");
    }

    #[tokio::test]
    async fn allows_plain_env_in_non_production() {
        std::env::set_var("DEV_ONLY_SECRET", "plain-dev");

        let secrets =
            LoadedSecrets::load(&[SecretSpec::required("DEV_ONLY_SECRET")], "development")
                .await
                .unwrap();

        let value = secrets
            .require_plain_string("DEV_ONLY_SECRET")
            .await
            .unwrap();
        std::env::remove_var("DEV_ONLY_SECRET");
        assert_eq!(value, "plain-dev");
    }

    #[tokio::test]
    async fn missing_optional_secret_returns_none() {
        let secrets =
            LoadedSecrets::load(&[SecretSpec::optional("OPTIONAL_SECRET")], "development")
                .await
                .unwrap();
        assert_eq!(
            secrets
                .optional_plain_string("OPTIONAL_SECRET")
                .await
                .unwrap(),
            None
        );

        clear_runtime_vars(&["OPTIONAL_SECRET"]);
    }
}
