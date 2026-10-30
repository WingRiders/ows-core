//! One directory-of-JSON-files store, shared by every record kept in the vault
//! (wallets today). A record type supplies its directory and whether it holds
//! secret material; the store does the rest.

use std::fs;
use std::path::{Path, PathBuf};

use ows_core::Config;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::OwsLibError;

pub(crate) trait VaultRecord: Serialize + DeserializeOwned + Clone {
    /// Directory under the vault root, e.g. `"wallets"`.
    const DIR: &'static str;
    /// Secret records get a 0700 directory and vault root, 0600 files, and a
    /// loose-permission warning when listed.
    const SECRET: bool;
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn created_at(&self) -> &str;
}

/// Why a lookup by id or name did not yield exactly one record.
#[derive(Debug)]
pub(crate) enum Lookup {
    NotFound,
    Ambiguous { count: usize },
    Failed(OwsLibError),
}

impl From<OwsLibError> for Lookup {
    fn from(e: OwsLibError) -> Self {
        Lookup::Failed(e)
    }
}

/// Set directory permissions to 0o700 (owner-only).
#[cfg(unix)]
fn set_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    if let Err(e) = fs::set_permissions(path, perms) {
        eprintln!(
            "warning: failed to set permissions on {}: {e}",
            path.display()
        );
    }
}

/// Set file permissions to 0o600 (owner read/write only).
#[cfg(unix)]
fn set_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    if let Err(e) = fs::set_permissions(path, perms) {
        eprintln!(
            "warning: failed to set permissions on {}: {e}",
            path.display()
        );
    }
}

/// Warn if a directory has permissions more open than 0o700.
#[cfg(unix)]
pub fn check_vault_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            eprintln!(
                "warning: {} has permissions {:04o}, expected 0700",
                path.display(),
                mode
            );
        }
    }
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) {}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) {}

#[cfg(not(unix))]
pub fn check_vault_permissions(_path: &Path) {}

/// Resolve the vault path: use explicit path if provided, otherwise default (~/.ows).
pub fn resolve_vault_path(vault_path: Option<&Path>) -> PathBuf {
    match vault_path {
        Some(p) => p.to_path_buf(),
        None => Config::default().vault_path,
    }
}

/// The record directory, created if necessary (with strict permissions for secret records).
pub(crate) fn dir<T: VaultRecord>(vault_path: Option<&Path>) -> Result<PathBuf, OwsLibError> {
    let root = resolve_vault_path(vault_path);
    let dir = root.join(T::DIR);
    fs::create_dir_all(&dir)?;
    if T::SECRET {
        set_dir_permissions(&root);
        set_dir_permissions(&dir);
    }
    Ok(dir)
}

pub(crate) fn save<T: VaultRecord>(
    record: &T,
    vault_path: Option<&Path>,
) -> Result<(), OwsLibError> {
    let dir = dir::<T>(vault_path)?;
    let path = dir.join(format!("{}.json", record.id()));
    let json = serde_json::to_string_pretty(record)?;
    fs::write(&path, json)?;
    if T::SECRET {
        set_file_permissions(&path);
    }
    Ok(())
}

/// All records, newest first. Unreadable or unparsable files are skipped with a warning.
pub(crate) fn list<T: VaultRecord>(vault_path: Option<&Path>) -> Result<Vec<T>, OwsLibError> {
    let dir = dir::<T>(vault_path)?;
    if T::SECRET {
        check_vault_permissions(&dir);
    }

    let mut records = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(records),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<T>(&contents) {
                Ok(r) => records.push(r),
                Err(e) => {
                    eprintln!("warning: skipping {}: {e}", path.display());
                }
            },
            Err(e) => {
                eprintln!("warning: skipping {}: {e}", path.display());
            }
        }
    }

    records.sort_by(|a, b| b.created_at().cmp(a.created_at()));
    Ok(records)
}

/// Exact id first, then name (case-sensitive).
pub(crate) fn find<T: VaultRecord>(
    name_or_id: &str,
    vault_path: Option<&Path>,
) -> Result<T, Lookup> {
    let records = list::<T>(vault_path)?;

    if let Some(r) = records.iter().find(|r| r.id() == name_or_id) {
        return Ok(r.clone());
    }

    let matches: Vec<&T> = records.iter().filter(|r| r.name() == name_or_id).collect();
    match matches.len() {
        0 => Err(Lookup::NotFound),
        1 => Ok(matches[0].clone()),
        count => Err(Lookup::Ambiguous { count }),
    }
}

pub(crate) fn delete<T: VaultRecord>(id: &str, vault_path: Option<&Path>) -> Result<(), Lookup> {
    let dir = dir::<T>(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(Lookup::NotFound);
    }
    fs::remove_file(&path).map_err(OwsLibError::from)?;
    Ok(())
}

pub(crate) fn name_exists<T: VaultRecord>(
    name: &str,
    vault_path: Option<&Path>,
) -> Result<bool, OwsLibError> {
    Ok(list::<T>(vault_path)?.iter().any(|r| r.name() == name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Clone, Debug)]
    struct TestRecord {
        id: String,
        name: String,
        created_at: String,
    }

    impl VaultRecord for TestRecord {
        const DIR: &'static str = "test-records";
        const SECRET: bool = true;
        fn id(&self) -> &str {
            &self.id
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn created_at(&self) -> &str {
            &self.created_at
        }
    }

    fn rec(id: &str, name: &str, created_at: &str) -> TestRecord {
        TestRecord {
            id: id.into(),
            name: name.into(),
            created_at: created_at.into(),
        }
    }

    #[test]
    fn skips_unparsable_files() {
        let vault = tempfile::tempdir().unwrap();
        save(&rec("a", "a", "2024-01-01"), Some(vault.path())).unwrap();
        let d = dir::<TestRecord>(Some(vault.path())).unwrap();
        fs::write(d.join("broken.json"), "{ not json").unwrap();
        fs::write(d.join("note.txt"), "ignored").unwrap();
        let all = list::<TestRecord>(Some(vault.path())).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "a");
    }

    #[test]
    fn lists_newest_first() {
        let vault = tempfile::tempdir().unwrap();
        save(&rec("old", "x", "2024-01-01T00:00:00Z"), Some(vault.path())).unwrap();
        save(&rec("new", "y", "2025-01-01T00:00:00Z"), Some(vault.path())).unwrap();
        let ids: Vec<_> = list::<TestRecord>(Some(vault.path()))
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, ["new", "old"]);
    }

    #[test]
    fn finds_id_before_name() {
        let vault = tempfile::tempdir().unwrap();
        save(&rec("one", "two", "2024-01-01"), Some(vault.path())).unwrap();
        save(&rec("two", "other", "2024-01-02"), Some(vault.path())).unwrap();
        let found = find::<TestRecord>("two", Some(vault.path())).unwrap();
        assert_eq!(found.id, "two");
        let by_name = find::<TestRecord>("other", Some(vault.path())).unwrap();
        assert_eq!(by_name.id, "two");
    }

    #[test]
    fn ambiguous_name_reports_the_count() {
        let vault = tempfile::tempdir().unwrap();
        save(&rec("a", "same", "2024-01-01"), Some(vault.path())).unwrap();
        save(&rec("b", "same", "2024-01-02"), Some(vault.path())).unwrap();
        match find::<TestRecord>("same", Some(vault.path())) {
            Err(Lookup::Ambiguous { count: 2 }) => {}
            other => panic!("expected Ambiguous {{ count: 2 }}, got {other:?}"),
        }
    }

    #[test]
    fn missing_id_is_not_found() {
        let vault = tempfile::tempdir().unwrap();
        assert!(matches!(
            find::<TestRecord>("nope", Some(vault.path())),
            Err(Lookup::NotFound)
        ));
        assert!(matches!(
            delete::<TestRecord>("nope", Some(vault.path())),
            Err(Lookup::NotFound)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn secret_store_sets_0700_and_0600() {
        use std::os::unix::fs::PermissionsExt;
        let vault = tempfile::tempdir().unwrap();
        save(&rec("p", "p", "2024-01-01"), Some(vault.path())).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(vault.path()), 0o700);
        assert_eq!(mode(&vault.path().join("test-records")), 0o700);
        assert_eq!(mode(&vault.path().join("test-records/p.json")), 0o600);
    }
}
