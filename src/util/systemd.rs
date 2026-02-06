//! Wrappers around systemd-creds commands.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;
use zeroize::Zeroizing;

/// Encrypt a secret using systemd-creds.
pub fn encrypt(
    with_key: &str,
    name: &str,
    input: &Path,
    output: &Path,
    tpm2_pcrs: Option<&str>,
) -> Result<()> {
    let mut cmd = Command::new("systemd-creds");
    cmd.arg("encrypt")
        .arg(format!("--with-key={}", with_key))
        .arg(format!("--name={}", name));
    if let Some(pcrs) = tpm2_pcrs {
        cmd.arg(format!("--tpm2-pcrs={}", pcrs));
    }
    cmd.arg(input).arg(output);
    run(cmd).context("systemd-creds encrypt")
}

/// Decrypt a credential to a file.
pub fn decrypt_to_file(input: &Path, output: &Path) -> Result<()> {
    let mut cmd = Command::new("systemd-creds");
    cmd.arg("decrypt");
    if let Some(name) = cred_name_from_path(input) {
        cmd.arg(format!("--name={}", name));
    }
    cmd.arg(input).arg(output);
    run(cmd).context("systemd-creds decrypt")
}

/// Decrypt a credential and return its contents (zeroized on drop).
pub fn decrypt_to_stdout(input: &Path, newline: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
    let mut cmd = Command::new("systemd-creds");
    cmd.arg("decrypt");
    if let Some(name) = cred_name_from_path(input) {
        cmd.arg(format!("--name={}", name));
    }
    cmd.arg(input);
    if let Some(newline) = newline {
        cmd.arg(format!("--newline={}", newline));
    }
    let output = cmd.output().context("run systemd-creds decrypt")?;
    if output.status.success() {
        return Ok(Zeroizing::new(output.stdout));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!("command failed: {}{}", stdout, stderr);
}

/// Run systemd-creds setup to ensure host key exists.
pub fn setup() -> Result<()> {
    let mut cmd = Command::new("systemd-creds");
    cmd.arg("setup");
    run(cmd).context("systemd-creds setup")
}

fn cred_name_from_path(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
}

/// Check whether TPM2 is available via systemd-creds.
pub fn has_tpm2() -> Result<bool> {
    let output = Command::new("systemd-creds")
        .args(["has-tpm2", "--quiet"])
        .output()
        .context("run systemd-creds has-tpm2")?;
    Ok(output.status.success())
}

/// Detailed TPM2 subsystem status.
#[derive(Debug, Clone)]
pub struct Tpm2Status {
    pub available: bool,
    pub firmware: bool,
    pub driver: bool,
    pub system: bool,
    pub subsystem: bool,
    pub libraries: bool,
}

impl Tpm2Status {
    fn parse(stdout: &str, success: bool) -> Self {
        let has = |keyword: &str| {
            stdout.contains(&format!("+{}", keyword))
        };
        Self {
            available: success,
            firmware: has("firmware"),
            driver: has("driver"),
            system: has("system"),
            subsystem: has("subsystem"),
            libraries: has("libraries"),
        }
    }

    /// Human-readable detail string for health output.
    pub fn detail(&self) -> String {
        let flags: Vec<&str> = [
            ("firmware", self.firmware),
            ("driver", self.driver),
            ("system", self.system),
            ("subsystem", self.subsystem),
            ("libraries", self.libraries),
        ]
        .iter()
        .filter_map(|(name, ok)| if *ok { Some(*name) } else { None })
        .collect();
        if flags.is_empty() {
            "no details".to_string()
        } else {
            flags.iter().map(|f| format!("+{}", f)).collect::<Vec<_>>().join(" ")
        }
    }
}

/// Detailed TPM2 subsystem status.
pub fn tpm2_status() -> Result<Tpm2Status> {
    let output = Command::new("systemd-creds")
        .arg("has-tpm2")
        .output()
        .context("run systemd-creds has-tpm2")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(Tpm2Status::parse(&stdout, output.status.success()))
}

fn run(mut cmd: Command) -> Result<()> {
    let output = cmd.output().context("run command")?;
    if output.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!("command failed: {}{}", stdout, stderr);
}
