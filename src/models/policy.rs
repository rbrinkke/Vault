//! Policy configuration for vault operations.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicySection {
    /// Allowed services (empty = no restriction).
    #[serde(default)]
    pub service_allowlist: Vec<String>,

    /// Minimum length for auto-generated secrets.
    #[serde(default)]
    pub min_auto_secret_length: Option<usize>,

    /// Reject host-only encryption when TPM2 is available.
    #[serde(default)]
    pub forbid_host_only_when_tpm2: bool,

    /// Forward audit entries to journald.
    #[serde(default)]
    pub journald_audit: bool,
}

impl PolicySection {
    fn normalize_service_name(service: &str) -> &str {
        service.strip_suffix(".service").unwrap_or(service)
    }

    pub fn is_service_allowed(&self, service: &str) -> bool {
        if self.service_allowlist.is_empty() {
            return true;
        }
        let svc = Self::normalize_service_name(service);
        self.service_allowlist
            .iter()
            .any(|s| Self::normalize_service_name(s) == svc)
    }
}
