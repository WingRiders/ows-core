//! Credential files in `<vault>/credentials/`. Wallet loaders read only `wallets/`, so a
//! credential is never reachable through a wallet command.

use std::path::{Component, Path};

use ows_core::{Credential, CREDENTIAL_FILE_VERSION};

use crate::error::OwsLibError;
use crate::record_store::{self, Lookup, VaultRecord};

impl VaultRecord for Credential {
    const DIR: &'static str = "credentials";
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

fn credential_error(lookup: Lookup, name_or_id: &str) -> OwsLibError {
    match lookup {
        Lookup::NotFound => OwsLibError::CredentialNotFound(name_or_id.to_string()),
        Lookup::Ambiguous { count } => OwsLibError::AmbiguousCredential {
            name: name_or_id.to_string(),
            count,
        },
        Lookup::Failed(e) => e,
    }
}

/// An id names its file, so it must be one plain file name: `../wallets/<id>` would reach a
/// wallet.
fn check_id(id: &str) -> Result<(), OwsLibError> {
    let mut components = Path::new(id).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) if name.to_str() == Some(id) => Ok(()),
        _ => Err(OwsLibError::InvalidInput(format!(
            "credential id {id:?} is not a plain file name"
        ))),
    }
}

fn check_version(credential: &Credential) -> Result<(), OwsLibError> {
    if credential.ows_version != CREDENTIAL_FILE_VERSION {
        return Err(OwsLibError::InvalidInput(format!(
            "credential '{}' is a version {} file, and this build reads only version {CREDENTIAL_FILE_VERSION}",
            credential.name, credential.ows_version
        )));
    }
    Ok(())
}

/// Save a credential file with strict permissions.
pub fn save_credential_file(
    credential: &Credential,
    vault_path: Option<&Path>,
) -> Result<(), OwsLibError> {
    check_id(&credential.id)?;
    record_store::save(credential, vault_path)
}

/// All credentials in the vault, newest first.
pub fn list_credential_files(vault_path: Option<&Path>) -> Result<Vec<Credential>, OwsLibError> {
    record_store::list(vault_path)
}

/// Look up a credential by exact ID first, then by name (case-sensitive). A file with an id that
/// is not a plain file name, or of another format version, is refused.
pub fn load_credential_by_name_or_id(
    name_or_id: &str,
    vault_path: Option<&Path>,
) -> Result<Credential, OwsLibError> {
    let credential = record_store::find::<Credential>(name_or_id, vault_path)
        .map_err(|l| credential_error(l, name_or_id))?;
    check_id(&credential.id)?;
    check_version(&credential)?;
    Ok(credential)
}

/// Delete a credential file from the vault by ID.
pub fn delete_credential_file(id: &str, vault_path: Option<&Path>) -> Result<(), OwsLibError> {
    check_id(id)?;
    record_store::delete::<Credential>(id, vault_path).map_err(|l| credential_error(l, id))
}

/// Check whether a credential with the given name already exists in the vault.
pub fn credential_name_exists(name: &str, vault_path: Option<&Path>) -> Result<bool, OwsLibError> {
    record_store::name_exists::<Credential>(name, vault_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault;
    use ows_core::{ChainType, CredentialOrigin};

    fn credential(id: &str, name: &str) -> Credential {
        Credential::new(
            id.to_string(),
            name.to_string(),
            ChainType::Midnight,
            "jubjub".to_string(),
            "ab".repeat(64),
            CredentialOrigin::Generated,
            serde_json::json!({"cipher": "aes-256-gcm"}),
        )
    }

    #[test]
    fn a_vault_without_credentials_lists_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(list_credential_files(Some(dir.path())).unwrap().is_empty());
    }

    #[test]
    fn credential_lookup_by_id_then_name() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        save_credential_file(&credential("id-1", "device"), v).unwrap();
        save_credential_file(&credential("id-2", "other"), v).unwrap();
        assert_eq!(
            load_credential_by_name_or_id("id-2", v).unwrap().name,
            "other"
        );
        assert_eq!(
            load_credential_by_name_or_id("device", v).unwrap().id,
            "id-1"
        );
        assert!(credential_name_exists("device", v).unwrap());
        assert!(!credential_name_exists("nope", v).unwrap());
        assert!(matches!(
            load_credential_by_name_or_id("nope", v),
            Err(OwsLibError::CredentialNotFound(_))
        ));
    }

    #[test]
    fn ambiguous_credential_name_reports_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        save_credential_file(&credential("id-1", "dup"), v).unwrap();
        save_credential_file(&credential("id-2", "dup"), v).unwrap();
        match load_credential_by_name_or_id("dup", v) {
            Err(OwsLibError::AmbiguousCredential { name, count }) => {
                assert_eq!(name, "dup");
                assert_eq!(count, 2);
            }
            other => panic!("expected AmbiguousCredential, got {other:?}"),
        }
    }

    #[test]
    fn deleting_a_missing_credential_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            delete_credential_file("ghost", Some(dir.path())),
            Err(OwsLibError::CredentialNotFound(_))
        ));
    }

    #[test]
    fn deleting_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        save_credential_file(&credential("id-1", "device"), v).unwrap();
        delete_credential_file("id-1", v).unwrap();
        assert!(list_credential_files(v).unwrap().is_empty());
    }

    #[test]
    fn an_id_that_is_not_a_plain_file_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let wallet = ows_core::EncryptedWallet::new(
            "w-1".to_string(),
            "w".to_string(),
            vec![],
            serde_json::json!({}),
            ows_core::KeyType::Mnemonic,
        );
        vault::save_encrypted_wallet(&wallet, v).unwrap();
        for id in ["../wallets/w-1", "a/b", "/abs", "..", ".", "", "id-1/"] {
            assert!(
                matches!(
                    save_credential_file(&credential(id, "x"), v),
                    Err(OwsLibError::InvalidInput(_))
                ),
                "saved {id:?}"
            );
            assert!(
                matches!(
                    delete_credential_file(id, v),
                    Err(OwsLibError::InvalidInput(_))
                ),
                "deleted {id:?}"
            );
        }
        assert_eq!(vault::list_encrypted_wallets(v).unwrap().len(), 1);

        let planted = credential("../wallets/w-1", "planted");
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();
        std::fs::write(
            dir.path().join("credentials/planted.json"),
            serde_json::to_string(&planted).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load_credential_by_name_or_id("planted", v),
            Err(OwsLibError::InvalidInput(_))
        ));
    }

    #[test]
    fn a_file_of_another_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let mut newer = credential("id-1", "device");
        newer.ows_version = CREDENTIAL_FILE_VERSION + 1;
        save_credential_file(&newer, v).unwrap();
        let err = load_credential_by_name_or_id("device", v).unwrap_err();
        assert!(
            matches!(&err, OwsLibError::InvalidInput(m) if m.contains("version 3") && m.contains("only version 2")),
            "{err}"
        );
        assert!(credential_name_exists("device", v).unwrap());
    }

    #[test]
    fn a_credential_is_not_a_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        save_credential_file(&credential("id-1", "x"), v).unwrap();
        assert!(matches!(
            vault::load_wallet_by_name_or_id("x", v),
            Err(OwsLibError::WalletNotFound(_))
        ));
        assert!(vault::list_encrypted_wallets(v).unwrap().is_empty());
    }
}
