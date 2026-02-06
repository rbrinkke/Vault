//! Vault configuration file model.

use crate::models::credential::CredentialMeta;
use crate::models::policy::PolicySection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultFile {
    #[serde(default)]
    pub vault: VaultSection,
    #[serde(default)]
    pub policy: PolicySection,
    #[serde(default)]
    pub credentials: Vec<CredentialMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSection {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub credstore_path: Option<String>,
}

impl Default for VaultSection {
    fn default() -> Self {
        Self {
            version: default_version(),
            credstore_path: None,
        }
    }
}

fn default_version() -> u32 {
    1
}
