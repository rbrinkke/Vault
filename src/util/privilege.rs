//! Privilege checks for root/sudo enforcement.

use anyhow::{bail, Result};

/// Check if the current process is running as root (euid 0).
pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Require root for a given action, or bail with an error.
pub fn require_root(action: &str) -> Result<()> {
    if !is_root() {
        bail!(
            "'{}' requires root privileges. Run with sudo.",
            action
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_root_returns_bool() {
        // Just verify it doesn't panic — actual value depends on test runner
        let _ = is_root();
    }
}
