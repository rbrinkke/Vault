//! Append-only audit trail for credential operations.

use crate::constants;
use crate::core::file_lock::FileLock;
use crate::core::paths::VaultPaths;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub actor: String,
    pub credential: String,
    #[serde(default = "default_metadata_only")]
    pub metadata_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    // Forensics-grade fields (all optional for backwards compatibility)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<AuditResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub with_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm2_pcrs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_version: Option<u8>,
}

fn default_metadata_only() -> bool {
    true
}

fn detect_actor() -> String {
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() {
            return format!("{}(sudo)", user);
        }
    }
    std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
}

/// Context for a forensics-grade audit entry.
pub struct AuditContext {
    pub action: String,
    pub credential: String,
    pub reason: Option<String>,
    pub output_mode: Option<String>,
    pub target_path: Option<String>,
    pub with_key: Option<String>,
    pub tpm2_pcrs: Option<String>,
    pub service_context: Option<String>,
}

/// Log an action with auto-detected actor (simple API).
pub fn log(paths: &VaultPaths, action: &str, credential: &str) -> Result<()> {
    log_action(paths, action, credential, &detect_actor())
}

/// Write a simple audit entry to the append-only log.
pub fn log_action(
    paths: &VaultPaths,
    action: &str,
    credential: &str,
    actor: &str,
) -> Result<()> {
    let _lock = FileLock::exclusive(&paths.audit_lock)?;
    let audit_path = paths.root.join("audit.log");
    let prev_hash = last_line_hash(&audit_path).unwrap_or(None);

    let mut entry = AuditEntry {
        timestamp: Utc::now(),
        action: action.to_string(),
        actor: actor.to_string(),
        credential: credential.to_string(),
        metadata_only: true,
        prev_hash,
        reason: None,
        result: None,
        output_mode: None,
        target_path: None,
        with_key: None,
        tpm2_pcrs: None,
        service_context: None,
        entry_hash: None,
        hash_version: Some(2),
    };

    // Compute entry hash using canonical JSON (without entry_hash field)
    entry.entry_hash = Some(compute_entry_hash(&entry)?);

    let line = serde_json::to_string(&entry).context("serialize audit entry")?;
    append_line(&audit_path, &line)?;
    Ok(())
}

/// Write a forensics-grade audit entry with full context and result.
pub fn log_with_result(
    paths: &VaultPaths,
    ctx: AuditContext,
    success: bool,
    error: Option<String>,
) -> Result<()> {
    let _lock = FileLock::exclusive(&paths.audit_lock)?;
    let audit_path = paths.root.join("audit.log");
    let prev_hash = last_line_hash(&audit_path).unwrap_or(None);

    let mut entry = AuditEntry {
        timestamp: Utc::now(),
        action: ctx.action,
        actor: detect_actor(),
        credential: ctx.credential,
        metadata_only: true,
        prev_hash,
        reason: ctx.reason,
        result: Some(AuditResult {
            success,
            error,
        }),
        output_mode: ctx.output_mode,
        target_path: ctx.target_path,
        with_key: ctx.with_key,
        tpm2_pcrs: ctx.tpm2_pcrs,
        service_context: ctx.service_context,
        entry_hash: None,
        hash_version: Some(2),
    };

    entry.entry_hash = Some(compute_entry_hash(&entry)?);

    let line = serde_json::to_string(&entry).context("serialize audit entry")?;
    append_line(&audit_path, &line)?;
    Ok(())
}

/// Compute canonical hash for an entry (excludes entry_hash field).
fn compute_entry_hash(entry: &AuditEntry) -> Result<String> {
    // Serialize to JSON value, remove entry_hash, then canonical-sort
    let mut value = serde_json::to_value(entry).context("serialize for hash")?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("entry_hash");
    }
    let canonical = canonicalize_value(&value);
    let canonical_str = serde_json::to_string(&canonical).context("serialize canonical json")?;
    let hash = Sha256::digest(canonical_str.as_bytes());
    Ok(format!("{:064x}", hash))
}

/// Canonicalize JSON by recursively sorting object keys.
/// Uses serde_json's serializer for correct escaping.
fn canonicalize_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonicalize_value(&map[k]));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize_value).collect())
        }
        other => other.clone(),
    }
}

fn append_line(audit_path: &std::path::Path, line: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)
        .with_context(|| format!("open audit log {}", audit_path.display()))?;
    writeln!(file, "{}", line).context("write audit entry")?;

    #[cfg(unix)]
    {
        let perm = fs::Permissions::from_mode(constants::AUDIT_LOG_MODE);
        fs::set_permissions(audit_path, perm)
            .context("set audit log permissions")?;
    }

    Ok(())
}

fn last_line_hash(path: &std::path::Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let len = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    if len == 0 {
        return Ok(None);
    }

    const CHUNK: u64 = 8192;
    let mut offset = len;
    let mut buf = Vec::new();

    while offset > 0 {
        let read_size = std::cmp::min(CHUNK, offset);
        offset -= read_size;
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("seek {}", path.display()))?;
        let mut tmp = vec![0u8; read_size as usize];
        file.read_exact(&mut tmp)
            .with_context(|| format!("read {}", path.display()))?;
        buf.splice(0..0, tmp);

        if buf.contains(&b'\n') || offset == 0 {
            for line in buf.split(|b| *b == b'\n').rev() {
                if line.iter().all(|b| b.is_ascii_whitespace()) {
                    continue;
                }
                // Try to extract entry_hash from the JSON
                if let Ok(entry) = serde_json::from_slice::<AuditEntry>(line) {
                    if let Some(hash) = entry.entry_hash {
                        return Ok(Some(hash));
                    }
                }
                // Fallback: raw SHA-256 of the line (v1 compatibility)
                let hash = Sha256::digest(line);
                return Ok(Some(format!("{:064x}", hash)));
            }
            return Ok(None);
        }
    }

    Ok(None)
}

/// Read audit entries from the log file.
pub fn read_log(paths: &VaultPaths, limit: Option<usize>) -> Result<Vec<AuditEntry>> {
    let audit_path = paths.root.join("audit.log");
    if !audit_path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(&audit_path)
        .with_context(|| format!("open audit log {}", audit_path.display()))?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    let mut malformed = 0usize;

    for line in reader.lines() {
        let line = line.context("read audit log line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(trimmed) {
            Ok(entry) => entries.push(entry),
            Err(_) => {
                malformed += 1;
            }
        }
    }

    if malformed > 0 {
        eprintln!("warning: {} malformed audit entries skipped", malformed);
    }

    if let Some(limit) = limit {
        if entries.len() > limit {
            entries = entries.split_off(entries.len() - limit);
        }
    }

    Ok(entries)
}

/// Verify the integrity of the audit chain. Returns (total, errors).
pub fn verify_chain(paths: &VaultPaths) -> Result<(usize, Vec<String>)> {
    let entries = read_log(paths, None)?;
    let mut errors = Vec::new();
    let mut prev_entry_hash: Option<String> = None;

    for (i, entry) in entries.iter().enumerate() {
        // Check prev_hash chain
        if i > 0 && entry.prev_hash != prev_entry_hash {
            errors.push(format!(
                "entry {}: prev_hash mismatch (expected {:?}, got {:?})",
                i + 1,
                prev_entry_hash,
                entry.prev_hash
            ));
        }

        // Verify entry_hash if present (v2)
        if entry.hash_version == Some(2) {
            if let Some(ref stored_hash) = entry.entry_hash {
                match compute_entry_hash(entry) {
                    Ok(computed) => {
                        if &computed != stored_hash {
                            errors.push(format!(
                                "entry {}: entry_hash mismatch (tampered?)",
                                i + 1
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(format!("entry {}: cannot compute hash: {}", i + 1, e));
                    }
                }
            }
        }

        // Compute hash for next entry's prev_hash check
        if let Some(ref hash) = entry.entry_hash {
            prev_entry_hash = Some(hash.clone());
        } else {
            // v1 entry: compute raw line hash
            let json = serde_json::to_string(entry).unwrap_or_default();
            let hash = Sha256::digest(json.as_bytes());
            prev_entry_hash = Some(format!("{:064x}", hash));
        }
    }

    Ok((entries.len(), errors))
}

/// Return the path to the audit log file.
pub fn audit_log_path(paths: &VaultPaths) -> std::path::PathBuf {
    paths.root.join("audit.log")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::paths::VaultPaths;
    use tempfile::TempDir;

    fn test_paths() -> (TempDir, VaultPaths) {
        let dir = TempDir::new().unwrap();
        let paths = VaultPaths::from_root(dir.path().to_path_buf());
        (dir, paths)
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            action: "create".into(),
            actor: "test".into(),
            credential: "db".into(),
            metadata_only: true,
            prev_hash: None,
            reason: None,
            result: None,
            output_mode: None,
            target_path: None,
            with_key: None,
            tpm2_pcrs: None,
            service_context: None,
            entry_hash: None,
            hash_version: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action, "create");
    }

    #[test]
    fn test_log_and_read_roundtrip() {
        let (_dir, paths) = test_paths();
        log_action(&paths, "create", "test_cred", "tester").unwrap();
        let entries = read_log(&paths, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "create");
        assert!(entries[0].entry_hash.is_some());
        assert_eq!(entries[0].hash_version, Some(2));
    }

    #[test]
    fn test_read_log_with_limit() {
        let (_dir, paths) = test_paths();
        for i in 0..5 {
            log_action(&paths, &format!("action_{}", i), "cred", "tester").unwrap();
        }
        let entries = read_log(&paths, Some(2)).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_read_log_nonexistent() {
        let (_dir, paths) = test_paths();
        let entries = read_log(&paths, None).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_canonical_json_deterministic() {
        let json1 = serde_json::json!({"b": 1, "a": 2});
        let json2 = serde_json::json!({"a": 2, "b": 1});
        let c1 = canonicalize_value(&json1);
        let c2 = canonicalize_value(&json2);
        let s1 = serde_json::to_string(&c1).unwrap();
        let s2 = serde_json::to_string(&c2).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1, r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn test_verify_chain_ok() {
        let (_dir, paths) = test_paths();
        log_action(&paths, "create", "cred1", "tester").unwrap();
        log_action(&paths, "rotate", "cred1", "tester").unwrap();
        log_action(&paths, "delete", "cred1", "tester").unwrap();
        let (total, errors) = verify_chain(&paths).unwrap();
        assert_eq!(total, 3);
        assert!(errors.is_empty(), "errors: {:?}", errors);
    }

    #[test]
    fn test_verify_chain_detects_tamper() {
        let (_dir, paths) = test_paths();
        log_action(&paths, "create", "cred1", "tester").unwrap();
        log_action(&paths, "rotate", "cred1", "tester").unwrap();

        // Tamper with the log
        let audit_path = paths.root.join("audit.log");
        let content = fs::read_to_string(&audit_path).unwrap();
        let tampered = content.replace("rotate", "DELETE_TAMPERED");
        fs::write(&audit_path, tampered).unwrap();

        let (total, errors) = verify_chain(&paths).unwrap();
        assert_eq!(total, 2);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_log_with_result() {
        let (_dir, paths) = test_paths();
        let ctx = AuditContext {
            action: "rotate".to_string(),
            credential: "db_pass".to_string(),
            reason: Some("scheduled rotation".to_string()),
            output_mode: None,
            target_path: None,
            with_key: Some("host+tpm2".to_string()),
            tpm2_pcrs: None,
            service_context: Some("myservice".to_string()),
        };
        log_with_result(&paths, ctx, true, None).unwrap();
        let entries = read_log(&paths, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason, Some("scheduled rotation".to_string()));
        assert!(entries[0].result.as_ref().unwrap().success);
        assert_eq!(entries[0].with_key, Some("host+tpm2".to_string()));
    }

    #[test]
    fn test_backwards_compatible_entry() {
        // Old-format entry (no new fields) should parse fine
        let json = r#"{"timestamp":"2025-01-01T00:00:00Z","action":"create","actor":"test","credential":"db","metadata_only":true}"#;
        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.action, "create");
        assert!(entry.reason.is_none());
        assert!(entry.entry_hash.is_none());
        assert!(entry.hash_version.is_none());
    }
}
