//! Optional journald forwarding via systemd-cat.
//!
//! Best-effort: failure to forward must not break vault operations.

use std::io::Write;
use std::process::{Command, Stdio};

pub fn systemd_cat_available() -> bool {
    Command::new("systemd-cat")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Forward a single log line to journald using `systemd-cat`.
pub fn forward_line(tag: &str, line: &str) {
    if !systemd_cat_available() {
        return;
    }

    let mut child = match Command::new("systemd-cat")
        .arg("-t")
        .arg(tag)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(line.as_bytes());
        let _ = stdin.write_all(b"\n");
    }

    let _ = child.wait();
}

