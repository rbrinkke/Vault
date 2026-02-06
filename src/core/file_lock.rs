//! File-based locking using flock(2) for concurrent access protection.

use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::path::Path;

/// An exclusive file lock. Released on drop (file close releases flock).
pub struct FileLock {
    _file: File,
}

impl FileLock {
    /// Acquire an exclusive lock, blocking until available.
    pub fn exclusive(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("open lock file {}", path.display()))?;
        file.lock_exclusive()
            .with_context(|| format!("acquire lock {}", path.display()))?;
        Ok(Self { _file: file })
    }

    /// Try to acquire an exclusive lock without blocking.
    /// Returns `Ok(Some(lock))` if acquired, `Ok(None)` if already held.
    pub fn try_exclusive(path: &Path) -> Result<Option<Self>> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("open lock file {}", path.display()))?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            // fs2 on Linux may return Other instead of WouldBlock
            Err(ref e) if e.raw_os_error() == Some(11) => Ok(None), // EAGAIN
            Err(e) => Err(e).with_context(|| format!("try lock {}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_exclusive_lock_acquired() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("test.lock");
        let lock = FileLock::exclusive(&lock_path).unwrap();
        assert!(lock_path.exists());
        drop(lock);
    }

    #[test]
    fn test_try_exclusive_returns_none_when_held() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("test.lock");
        let _lock = FileLock::exclusive(&lock_path).unwrap();
        let result = FileLock::try_exclusive(&lock_path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_lock_released_on_drop() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("test.lock");
        {
            let _lock = FileLock::exclusive(&lock_path).unwrap();
        }
        // Should be able to acquire again after drop
        let lock = FileLock::try_exclusive(&lock_path).unwrap();
        assert!(lock.is_some());
    }
}
