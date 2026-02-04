use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

pub fn encrypt(with_key: &str, name: &str, input: &Path, output: &Path) -> Result<()> {
    let mut cmd = Command::new("systemd-creds");
    cmd.arg("encrypt")
        .arg(format!("--with-key={}", with_key))
        .arg(format!("--name={}", name))
        .arg(input)
        .arg(output);
    run(cmd).context("systemd-creds encrypt")
}

pub fn decrypt_to_file(input: &Path, output: &Path) -> Result<()> {
    let mut cmd = Command::new("systemd-creds");
    cmd.arg("decrypt").arg(input).arg(output);
    run(cmd).context("systemd-creds decrypt")
}

pub fn decrypt_to_stdout(input: &Path, newline: Option<&str>) -> Result<Vec<u8>> {
    let mut cmd = Command::new("systemd-creds");
    cmd.arg("decrypt").arg(input);
    if let Some(newline) = newline {
        cmd.arg(format!("--newline={}", newline));
    }
    let output = cmd.output().context("run systemd-creds decrypt")?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!("command failed: {}{}", stdout, stderr);
}

pub fn setup() -> Result<()> {
    let mut cmd = Command::new("systemd-creds");
    cmd.arg("setup");
    run(cmd).context("systemd-creds setup")
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
