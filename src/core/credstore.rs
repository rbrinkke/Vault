use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct CredEntry {
    pub name: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified: Option<SystemTime>,
}

pub fn list_credentials(cred_dir: &Path) -> Result<Vec<CredEntry>> {
    let mut entries = Vec::new();
    let dir = fs::read_dir(cred_dir)
        .with_context(|| format!("open credstore directory {}", cred_dir.display()))?;
    for entry in dir {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = match path.file_name().and_then(|s| s.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if !file_name.ends_with(".cred") {
            continue;
        }
        let name = file_name.trim_end_matches(".cred").to_string();
        let meta = fs::metadata(&path)?;
        entries.push(CredEntry {
            name,
            path,
            size_bytes: meta.len(),
            modified: meta.modified().ok(),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}
