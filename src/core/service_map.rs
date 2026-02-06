//! Unified service map parser.
//!
//! Parses `services/*.conf` map files into structured entries.
//! Used by dropin generation, health checks, and migration verify.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// A parsed entry from a service map file.
#[derive(Debug, Clone)]
pub struct ServiceMapEntry {
    pub cred_name: String,
    pub cred_path: PathBuf,
    pub env_var: Option<String>,
    pub line_number: usize,
    pub is_custom_path: bool,
}

/// A warning produced during map validation.
#[derive(Debug, Clone)]
pub struct MapWarning {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for MapWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

/// Parse a service map file into structured entries.
///
/// Format per line: `CRED_NAME [ENVVAR]` or `name:path [ENVVAR]`
/// Lines starting with `#` (after optional whitespace) are comments.
pub fn parse_service_map(path: &Path, default_cred_dir: &Path) -> Result<Vec<ServiceMapEntry>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read map file {}", path.display()))?;
    parse_service_map_content(&content, default_cred_dir)
}

/// Parse service map content (testable without filesystem).
pub fn parse_service_map_content(
    content: &str,
    default_cred_dir: &Path,
) -> Result<Vec<ServiceMapEntry>> {
    let mut entries = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let line = raw_line.split('#').next().unwrap_or("");
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let raw = match parts.next() {
            Some(val) => val,
            None => continue,
        };
        let env_var = parts.next().map(|s| s.to_string());

        let (name, cred_path, is_custom) = if let Some((left, right)) = raw.split_once(':') {
            (left.to_string(), PathBuf::from(right), true)
        } else {
            (
                raw.to_string(),
                default_cred_dir.join(format!("{}.cred", raw)),
                false,
            )
        };

        // Validate credential name
        if name.is_empty() {
            bail!("empty credential name on line {}", line_num);
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        {
            bail!(
                "invalid credential name on line {}: only [a-zA-Z0-9._-] allowed",
                line_num
            );
        }

        // Validate custom paths
        if is_custom {
            let path_str = cred_path.to_string_lossy();
            if !cred_path.is_absolute() {
                bail!(
                    "custom credential path must be absolute on line {}: {}",
                    line_num,
                    path_str
                );
            }
            if path_str.contains("..") {
                bail!(
                    "path traversal not allowed on line {}: {}",
                    line_num,
                    path_str
                );
            }
        }

        if cred_path.to_string_lossy().contains(' ') {
            bail!(
                "credential path contains spaces on line {}: {}",
                line_num,
                cred_path.display()
            );
        }

        // Validate env var format
        if let Some(ref ev) = env_var {
            if !is_valid_env_var(ev) {
                bail!(
                    "invalid environment variable on line {}: '{}' (must match [A-Z][A-Z0-9_]*)",
                    line_num,
                    ev
                );
            }
        }

        entries.push(ServiceMapEntry {
            cred_name: name,
            cred_path,
            env_var,
            line_number: line_num,
            is_custom_path: is_custom,
        });
    }

    // Check for duplicate credential names
    for (i, entry) in entries.iter().enumerate() {
        for other in &entries[i + 1..] {
            if entry.cred_name == other.cred_name {
                bail!(
                    "duplicate credential '{}' on lines {} and {}",
                    entry.cred_name,
                    entry.line_number,
                    other.line_number
                );
            }
        }
    }

    Ok(entries)
}

/// Validate map entries against known credentials and credstore.
pub fn validate_map(
    entries: &[ServiceMapEntry],
    known_creds: &[String],
    credstore: &Path,
) -> Vec<MapWarning> {
    let mut warnings = Vec::new();

    for entry in entries {
        // Warn if credential not in vault.toml
        if !known_creds.iter().any(|c| c == &entry.cred_name) {
            warnings.push(MapWarning {
                line: entry.line_number,
                message: format!(
                    "credential '{}' not found in vault.toml",
                    entry.cred_name
                ),
            });
        }

        // Warn if .cred file doesn't exist
        let cred_file = if entry.is_custom_path {
            entry.cred_path.clone()
        } else {
            credstore.join(format!("{}.cred", entry.cred_name))
        };
        if !cred_file.exists() {
            warnings.push(MapWarning {
                line: entry.line_number,
                message: format!(
                    ".cred file not found: {}",
                    cred_file.display()
                ),
            });
        }
    }

    warnings
}

fn is_valid_env_var(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let content = "db_password DB_PASS_FILE\napi_token API_TOKEN_FILE\n";
        let entries = parse_service_map_content(content, Path::new("/creds")).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].cred_name, "db_password");
        assert_eq!(
            entries[0].cred_path,
            PathBuf::from("/creds/db_password.cred")
        );
        assert_eq!(entries[0].env_var, Some("DB_PASS_FILE".to_string()));
        assert!(!entries[0].is_custom_path);
    }

    #[test]
    fn test_parse_custom_path() {
        let content = "secret:/opt/custom/secret.cred SECRET_FILE\n";
        let entries = parse_service_map_content(content, Path::new("/creds")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cred_path, PathBuf::from("/opt/custom/secret.cred"));
        assert!(entries[0].is_custom_path);
    }

    #[test]
    fn test_parse_no_env_var() {
        let content = "db_password\n";
        let entries = parse_service_map_content(content, Path::new("/creds")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].env_var, None);
    }

    #[test]
    fn test_parse_comments_and_blanks() {
        let content = "# comment\n\ndb_password\n  # another\n";
        let entries = parse_service_map_content(content, Path::new("/creds")).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_parse_inline_comment() {
        let content = "db_password DB_PASS # my database\n";
        let entries = parse_service_map_content(content, Path::new("/creds")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].env_var, Some("DB_PASS".to_string()));
    }

    #[test]
    fn test_parse_invalid_name() {
        let content = "inv@lid_name\n";
        assert!(parse_service_map_content(content, Path::new("/creds")).is_err());
    }

    #[test]
    fn test_parse_empty_name() {
        let content = ":path\n";
        assert!(parse_service_map_content(content, Path::new("/creds")).is_err());
    }

    #[test]
    fn test_parse_duplicate_names() {
        let content = "db_password\ndb_password\n";
        assert!(parse_service_map_content(content, Path::new("/creds")).is_err());
    }

    #[test]
    fn test_parse_relative_custom_path() {
        let content = "secret:relative/path.cred\n";
        assert!(parse_service_map_content(content, Path::new("/creds")).is_err());
    }

    #[test]
    fn test_parse_path_traversal() {
        let content = "secret:/opt/../etc/passwd\n";
        assert!(parse_service_map_content(content, Path::new("/creds")).is_err());
    }

    #[test]
    fn test_parse_invalid_env_var() {
        let content = "db_password lower_case\n";
        assert!(parse_service_map_content(content, Path::new("/creds")).is_err());
    }

    #[test]
    fn test_parse_env_var_starting_with_digit() {
        let content = "db_password 1BAD\n";
        assert!(parse_service_map_content(content, Path::new("/creds")).is_err());
    }

    #[test]
    fn test_valid_env_var() {
        assert!(is_valid_env_var("DB_PASS"));
        assert!(is_valid_env_var("A"));
        assert!(is_valid_env_var("MY_VAR_123"));
        assert!(!is_valid_env_var(""));
        assert!(!is_valid_env_var("lowercase"));
        assert!(!is_valid_env_var("1START"));
        assert!(!is_valid_env_var("HAS-DASH"));
    }

    #[test]
    fn test_validate_map_warnings() {
        let entries = vec![
            ServiceMapEntry {
                cred_name: "exists".to_string(),
                cred_path: PathBuf::from("/nonexistent/exists.cred"),
                env_var: None,
                line_number: 1,
                is_custom_path: false,
            },
            ServiceMapEntry {
                cred_name: "missing".to_string(),
                cred_path: PathBuf::from("/nonexistent/missing.cred"),
                env_var: None,
                line_number: 2,
                is_custom_path: false,
            },
        ];
        let known = vec!["exists".to_string()];
        let warnings = validate_map(&entries, &known, Path::new("/nonexistent"));
        // "missing" not in known_creds, both .cred files don't exist
        assert!(warnings.iter().any(|w| w.message.contains("'missing' not found in vault.toml")));
        assert!(warnings.iter().any(|w| w.message.contains(".cred file not found")));
    }

    #[test]
    fn test_parse_empty_content() {
        let entries = parse_service_map_content("", Path::new("/creds")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_line_numbers() {
        let content = "# comment\n\nfirst\nsecond\n";
        let entries = parse_service_map_content(content, Path::new("/creds")).unwrap();
        assert_eq!(entries[0].line_number, 3);
        assert_eq!(entries[1].line_number, 4);
    }
}
