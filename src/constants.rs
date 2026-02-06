//! Centralized constants for permissions, paths, and limits.

/// Default vault root directory.
pub const DEFAULT_VAULT_ROOT: &str = "/opt/services/vault";

/// Path to the systemd host encryption key.
pub const HOST_KEY_PATH: &str = "/var/lib/systemd/credential.secret";

/// Permission mode for the credstore directory.
pub const CREDSTORE_DIR_MODE: u32 = 0o700;

/// Permission mode for individual credential files.
pub const CRED_FILE_MODE: u32 = 0o600;

/// Permission mode for vault.toml.
pub const VAULT_TOML_MODE: u32 = 0o640;

/// Permission mode for the audit log.
pub const AUDIT_LOG_MODE: u32 = 0o640;

/// Permission mode for the services directory.
pub const SERVICES_DIR_MODE: u32 = 0o755;

/// Permission mode for the units directory.
pub const UNITS_DIR_MODE: u32 = 0o755;

/// Maximum secret size in bytes (1 MiB).
pub const MAX_SECRET_SIZE: usize = 1_048_576;

/// File extension for encrypted credential files.
pub const CRED_EXTENSION: &str = ".cred";

/// Valid encryption key types for systemd-creds.
pub const VALID_KEY_TYPES: &[&str] = &["host", "tpm2", "host+tpm2", "auto"];

/// Default key type when TPM2 is available.
pub const DEFAULT_KEY_TYPE_WITH_TPM2: &str = "host+tpm2";

/// Default key type when TPM2 is not available.
pub const DEFAULT_KEY_TYPE_WITHOUT_TPM2: &str = "host";
