//! Test-only systemd leak checks.
//!
//! This does NOT modify /etc/systemd/system. It uses transient units via `systemd-run`.

use crate::cli::CliContext;
use crate::constants;
use crate::util::{fs as vault_fs, systemd};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use zeroize::Zeroizing;

#[derive(Subcommand, Debug)]
pub enum TestCommand {
    /// Run a transient unit and verify secrets don't leak to args/journald
    Run(TestRunArgs),
}

#[derive(Args, Debug)]
pub struct TestRunArgs {
    /// Output format (text|json)
    #[arg(long, default_value = "text")]
    pub format: String,

    /// How long the transient unit should keep running (seconds)
    #[arg(long, default_value_t = 15)]
    pub runtime_sec: u64,

    /// Key type for encrypting the test credential (default: host for maximum compatibility)
    #[arg(long, default_value = "host")]
    pub with_key: String,

    /// Do not call systemd-run (only generate artifacts)
    #[arg(long)]
    pub no_systemd: bool,
}

#[derive(Debug, Clone, Serialize)]
struct CheckResult {
    name: String,
    ok: bool,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct TestReport {
    unit: String,
    vault_root: String,
    cred_name: String,
    cred_path: String,
    checks: Vec<CheckResult>,
}

pub fn run(ctx: &CliContext, cmd: TestCommand) -> Result<()> {
    match cmd {
        TestCommand::Run(args) => run_leak_test(ctx, args),
    }
}

fn run_leak_test(_ctx: &CliContext, args: TestRunArgs) -> Result<()> {
    // Root is strongly recommended for systemd-run + /proc inspection; enforce to avoid surprises.
    crate::util::privilege::require_root("test run")?;

    if args.format != "text" && args.format != "json" {
        bail!("invalid format: {} (use text|json)", args.format);
    }

    // Preflight binaries
    let mut checks: Vec<CheckResult> = Vec::new();
    checks.push(check_bin("systemd-run")?);
    checks.push(check_bin("systemctl")?);
    checks.push(check_bin("journalctl")?);
    checks.push(check_bin("systemd-creds")?);

    // Create a temp vault root under /tmp (keeps tests isolated from real credstore).
    // NOTE: using /dev/shm triggers credential setup failures on some systems (Protocol error).
    let tmp_root = TempDir::new().context("create temp dir")?;
    let vault_root = tmp_root.path().to_path_buf();
    let credstore = vault_root.join("credstore");
    fs::create_dir_all(&credstore).context("create temp credstore")?;
    vault_fs::set_permissions(&credstore, constants::CREDSTORE_DIR_MODE)?;

    // Create a random secret (kept in memory) and encrypt it as a .cred file.
    let cred_name = format!("leak_test_{}", random_id(10));
    let secret: Zeroizing<String> = Zeroizing::new(random_secret(48));

    // Write temp plaintext to credstore (0700 dir), then encrypt; temp file is removed automatically.
    let tmp_plain = tempfile::Builder::new()
        .prefix(".secret-")
        .tempfile_in(&credstore)
        .context("create temp plaintext secret")?;
    {
        let mut f = tmp_plain.as_file();
        f.write_all(secret.as_bytes()).context("write plaintext secret")?;
        f.sync_all().ok(); // best-effort
    }
    let cred_path = credstore.join(format!("{}{}", cred_name, constants::CRED_EXTENSION));
    let key_type = resolve_with_key(&args.with_key)?;
    systemd::encrypt(
        &key_type,
        &cred_name,
        tmp_plain.path(),
        &cred_path,
        None,
    )
    .context("encrypt test credential")?;
    vault_fs::set_permissions(&cred_path, constants::CRED_FILE_MODE)?;

    let unit = format!("vault-leak-test-{}.service", random_id(8));

    if args.no_systemd {
        let report = TestReport {
            unit,
            vault_root: vault_root.display().to_string(),
            cred_name,
            cred_path: cred_path.display().to_string(),
            checks,
        };
        return print_report(&report, &args.format);
    }

    // Start transient unit. It prints only byte size and then sleeps a bit to allow inspection.
    start_transient_unit(&unit, &cred_name, &cred_path, args.runtime_sec)?;

    // Wait until the unit is active (or failed) so MainPID isn't 0.
    let (active, state_detail) = wait_unit_active_or_failed(&unit, 3000)?;
    checks.push(CheckResult {
        name: "unit_state".into(),
        ok: active,
        detail: state_detail,
    });

    // Resolve PID
    let pid = unit_main_pid(&unit).context("resolve unit pid")?;
    if pid <= 1 {
        checks.push(CheckResult {
            name: "main_pid".into(),
            ok: false,
            detail: format!("unexpected MainPID={}", pid),
        });
    } else {
        checks.push(CheckResult {
            name: "main_pid".into(),
            ok: true,
            detail: format!("MainPID={}", pid),
        });
    }

    // Check process args/cmdline do not contain the secret
    if pid > 1 {
        checks.push(check_proc_cmdline(pid, &secret)?);
        checks.push(check_ps_args(pid, &secret)?);
    }

    // Check journald does not contain the secret
    checks.push(check_journal_no_secret(&unit, &secret)?);

    // Cleanup transient unit
    stop_transient_unit(&unit).ok();

    let report = TestReport {
        unit,
        vault_root: vault_root.display().to_string(),
        cred_name,
        cred_path: cred_path.display().to_string(),
        checks,
    };
    print_report(&report, &args.format)
}

fn print_report(report: &TestReport, format: &str) -> Result<()> {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!("Test unit: {}", report.unit);
    println!("Vault root: {}", report.vault_root);
    println!("Credential: {} -> {}", report.cred_name, report.cred_path);
    for c in &report.checks {
        let status = if c.ok { "PASS" } else { "FAIL" };
        println!("  [{}] {}: {}", status, c.name, c.detail);
    }
    let failed = report.checks.iter().filter(|c| !c.ok).count();
    if failed > 0 {
        bail!("{} check(s) failed", failed);
    }
    Ok(())
}

fn check_bin(name: &str) -> Result<CheckResult> {
    let ok = Command::new(name).arg("--version").output().is_ok();
    Ok(CheckResult {
        name: format!("bin:{}", name),
        ok,
        detail: if ok {
            "available".into()
        } else {
            "missing".into()
        },
    })
}

fn random_id(len: usize) -> String {
    OsRng
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn random_secret(len: usize) -> String {
    // Alnum is fine for leak-detection; no need for special chars.
    random_id(len)
}

fn resolve_with_key(s: &str) -> Result<String> {
    let s = s.trim();
    if !constants::VALID_KEY_TYPES.contains(&s) {
        bail!(
            "invalid key type '{}', must be one of: {}",
            s,
            constants::VALID_KEY_TYPES.join(", ")
        );
    }
    if s == "auto" {
        if systemd::has_tpm2().unwrap_or(false) {
            Ok(constants::DEFAULT_KEY_TYPE_WITH_TPM2.to_string())
        } else {
            Ok(constants::DEFAULT_KEY_TYPE_WITHOUT_TPM2.to_string())
        }
    } else {
        Ok(s.to_string())
    }
}

fn start_transient_unit(unit: &str, cred_name: &str, cred_path: &Path, runtime_sec: u64) -> Result<()> {
    // NOTE: No secrets in args; only file paths.
    let script = format!(
        "set -euo pipefail; \
         f=\"/run/credentials/{}/{}\"; \
         test -f \"$f\"; \
         bytes=$(stat -c %s \"$f\"); \
         echo \"credential_bytes=$bytes\"; \
         sleep {};",
        unit,
        cred_name,
        runtime_sec
    );

    let status = Command::new("systemd-run")
        .arg("--unit")
        .arg(unit)
        .arg("-p")
        .arg("Type=simple")
        .arg("-p")
        .arg(format!(
            "LoadCredentialEncrypted={}:{}",
            cred_name,
            cred_path.display()
        ))
        .arg("-p")
        .arg(format!("RuntimeMaxSec={}", runtime_sec + 10))
        .arg("/bin/bash")
        .arg("-lc")
        .arg(script)
        .status()
        .context("systemd-run")?;

    if !status.success() {
        bail!("systemd-run failed for unit '{}'", unit);
    }
    Ok(())
}

fn wait_unit_active_or_failed(unit: &str, timeout_ms: u64) -> Result<(bool, String)> {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < timeout_ms as u128 {
        let out = Command::new("systemctl")
            .arg("show")
            .arg(unit)
            .arg("-p")
            .arg("ActiveState")
            .arg("-p")
            .arg("SubState")
            .arg("-p")
            .arg("Result")
            .arg("--no-pager")
            .output()
            .context("systemctl show state")?;
        let s = String::from_utf8_lossy(&out.stdout);

        let mut active_state = None::<String>;
        let mut sub_state = None::<String>;
        let mut result = None::<String>;
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("ActiveState=") {
                active_state = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("SubState=") {
                sub_state = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Result=") {
                result = Some(v.trim().to_string());
            }
        }

        let as_ = active_state.unwrap_or_else(|| "?".into());
        let ss = sub_state.unwrap_or_else(|| "?".into());
        let r = result.unwrap_or_else(|| "?".into());
        let detail = format!("ActiveState={} SubState={} Result={}", as_, ss, r);

        if as_ == "active" || ss == "running" {
            return Ok((true, detail));
        }
        if as_ == "failed" || r == "exit-code" {
            return Ok((false, detail));
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok((false, "timeout waiting for unit to become active".into()))
}

fn unit_main_pid(unit: &str) -> Result<i32> {
    let out = Command::new("systemctl")
        .arg("show")
        .arg("-p")
        .arg("MainPID")
        .arg("--value")
        .arg(unit)
        .output()
        .context("systemctl show MainPID")?;
    if !out.status.success() {
        bail!("systemctl show failed");
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.trim().parse::<i32>().unwrap_or(0))
}

fn check_proc_cmdline(pid: i32, secret: &str) -> Result<CheckResult> {
    let path = PathBuf::from(format!("/proc/{}/cmdline", pid));
    let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let s = String::from_utf8_lossy(&data).to_string();
    let ok = !s.contains(secret);
    Ok(CheckResult {
        name: "proc:cmdline".into(),
        ok,
        detail: if ok {
            "secret not present".into()
        } else {
            "secret leaked into /proc/<pid>/cmdline".into()
        },
    })
}

fn check_ps_args(pid: i32, secret: &str) -> Result<CheckResult> {
    let out = Command::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("args=")
        .output()
        .context("ps")?;
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    let ok = !s.contains(secret);
    Ok(CheckResult {
        name: "ps:args".into(),
        ok,
        detail: if ok {
            "secret not present".into()
        } else {
            "secret leaked into ps args".into()
        },
    })
}

fn check_journal_no_secret(unit: &str, secret: &str) -> Result<CheckResult> {
    let out = Command::new("journalctl")
        .arg("-u")
        .arg(unit)
        .arg("--no-pager")
        .output()
        .context("journalctl")?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let ok = !combined.contains(secret);
    Ok(CheckResult {
        name: "journalctl".into(),
        ok,
        detail: if ok {
            "secret not present".into()
        } else {
            "secret leaked into journald".into()
        },
    })
}

fn stop_transient_unit(unit: &str) -> Result<()> {
    use std::process::Stdio;
    let _ = Command::new("systemctl")
        .arg("stop")
        .arg(unit)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("systemctl")
        .arg("reset-failed")
        .arg(unit)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}
