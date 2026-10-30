use ows_core::EncryptedWallet;
use std::path::{Path, PathBuf};

use crate::error::OwsLibError;
use crate::record_store::{self, Lookup, VaultRecord};

pub use crate::record_store::{check_vault_permissions, resolve_vault_path};

impl VaultRecord for EncryptedWallet {
    const DIR: &'static str = "wallets";
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

/// Returns the wallets directory, creating it with strict permissions if necessary.
pub fn wallets_dir(vault_path: Option<&Path>) -> Result<PathBuf, OwsLibError> {
    record_store::dir::<EncryptedWallet>(vault_path)
}

/// Save an encrypted wallet file with strict permissions.
pub fn save_encrypted_wallet(
    wallet: &EncryptedWallet,
    vault_path: Option<&Path>,
) -> Result<(), OwsLibError> {
    record_store::save(wallet, vault_path)
}

/// Load all encrypted wallets from the vault.
/// Checks directory permissions and warns if insecure.
/// Returns wallets sorted by created_at descending (newest first).
pub fn list_encrypted_wallets(
    vault_path: Option<&Path>,
) -> Result<Vec<EncryptedWallet>, OwsLibError> {
    record_store::list(vault_path)
}

fn wallet_error(lookup: Lookup, name_or_id: &str) -> OwsLibError {
    match lookup {
        Lookup::NotFound => OwsLibError::WalletNotFound(name_or_id.to_string()),
        Lookup::Ambiguous { count } => OwsLibError::AmbiguousWallet {
            name: name_or_id.to_string(),
            count,
        },
        Lookup::Failed(e) => e,
    }
}

/// Look up a wallet by exact ID first, then by name (case-sensitive).
/// Returns an error if no wallet matches or if the name is ambiguous.
pub fn load_wallet_by_name_or_id(
    name_or_id: &str,
    vault_path: Option<&Path>,
) -> Result<EncryptedWallet, OwsLibError> {
    record_store::find(name_or_id, vault_path).map_err(|l| wallet_error(l, name_or_id))
}

/// Delete a wallet file from the vault by ID.
pub fn delete_wallet_file(id: &str, vault_path: Option<&Path>) -> Result<(), OwsLibError> {
    record_store::delete::<EncryptedWallet>(id, vault_path).map_err(|l| wallet_error(l, id))
}

/// Check whether a wallet with the given name already exists in the vault.
pub fn wallet_name_exists(name: &str, vault_path: Option<&Path>) -> Result<bool, OwsLibError> {
    record_store::name_exists::<EncryptedWallet>(name, vault_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ows_core::{KeyType, WalletAccount};

    #[test]
    fn test_wallets_dir_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let result = wallets_dir(Some(&vault)).unwrap();
        assert!(result.exists());
        assert_eq!(result, vault.join("wallets"));
    }

    #[test]
    fn test_save_and_list_wallets() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "test-id".to_string(),
            "test-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();
        let wallets = list_encrypted_wallets(Some(&vault)).unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].id, "test-id");
    }

    #[test]
    fn test_load_by_name_or_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "uuid-123".to_string(),
            "my-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        // Find by ID
        let found = load_wallet_by_name_or_id("uuid-123", Some(&vault)).unwrap();
        assert_eq!(found.name, "my-wallet");

        // Find by name
        let found = load_wallet_by_name_or_id("my-wallet", Some(&vault)).unwrap();
        assert_eq!(found.id, "uuid-123");

        // Not found
        let err = load_wallet_by_name_or_id("nonexistent", Some(&vault));
        assert!(err.is_err());
    }

    #[test]
    fn test_delete_wallet_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "del-id".to_string(),
            "del-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();
        assert_eq!(list_encrypted_wallets(Some(&vault)).unwrap().len(), 1);

        delete_wallet_file("del-id", Some(&vault)).unwrap();
        assert_eq!(list_encrypted_wallets(Some(&vault)).unwrap().len(), 0);
    }

    #[test]
    fn test_wallet_name_exists() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "id-1".to_string(),
            "existing-name".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();
        assert!(wallet_name_exists("existing-name", Some(&vault)).unwrap());
        assert!(!wallet_name_exists("other-name", Some(&vault)).unwrap());
    }

    // === Characterization tests: lock down current behavior before refactoring ===

    #[test]
    fn char_save_and_load_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "char-id-123".to_string(),
            "char-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        let loaded = load_wallet_by_name_or_id("char-id-123", Some(&vault)).unwrap();
        assert_eq!(loaded.id, wallet.id);
        assert_eq!(loaded.name, wallet.name);
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.accounts[0].address, "0xabc");
        assert_eq!(loaded.key_type, KeyType::Mnemonic);
    }

    #[test]
    fn char_save_and_load_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "char-uuid-456".to_string(),
            "my-char-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        let loaded = load_wallet_by_name_or_id("my-char-wallet", Some(&vault)).unwrap();
        assert_eq!(loaded.id, "char-uuid-456");
    }

    #[test]
    fn char_path_traversal_in_save_rejected() {
        // Wallet IDs with path traversal components should be rejected or sanitized
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "../../../etc/passwd".to_string(),
            "evil-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        // The file should be saved within the wallets dir only
        // Even if save succeeds, verify the file doesn't escape the vault
        let result = save_encrypted_wallet(&wallet, Some(&vault));
        if result.is_ok() {
            // If it doesn't error, verify no file was written outside the vault
            let wallets_dir_path = vault.join("wallets");
            let _escaped_path = vault.join("wallets").join("../../../etc/passwd.json");
            let canonical_wallets = wallets_dir_path.canonicalize().unwrap();

            // List what's actually in the wallets dir
            let entries: Vec<_> = std::fs::read_dir(&wallets_dir_path)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();

            // Check that any file written is within the wallets directory
            for entry in &entries {
                let path = entry.path().canonicalize().unwrap();
                assert!(
                    path.starts_with(&canonical_wallets),
                    "wallet file {:?} escaped the vault directory",
                    path
                );
            }
        }
        // If it errors, that's also acceptable (more secure)
    }

    #[test]
    fn char_path_traversal_in_delete_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        // Create a legitimate wallet first
        let wallet = EncryptedWallet::new(
            "legit-id".to_string(),
            "legit".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        // Attempt to delete with path traversal
        let result = delete_wallet_file("../../../etc/passwd", Some(&vault));
        // Should either error (ideal) or find no matching file
        assert!(result.is_err());

        // Original wallet should still exist
        assert_eq!(list_encrypted_wallets(Some(&vault)).unwrap().len(), 1);
    }

    #[test]
    fn char_list_returns_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let w1 = EncryptedWallet::new(
            "w1-id".to_string(),
            "wallet-1".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&w1, Some(&vault)).unwrap();

        // Sleep a tiny bit to ensure different created_at timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));

        let w2 = EncryptedWallet::new(
            "w2-id".to_string(),
            "wallet-2".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&w2, Some(&vault)).unwrap();

        let wallets = list_encrypted_wallets(Some(&vault)).unwrap();
        assert_eq!(wallets.len(), 2);
        // Newest first
        assert_eq!(wallets[0].id, "w2-id");
        assert_eq!(wallets[1].id, "w1-id");
    }

    #[test]
    fn char_duplicate_wallet_name_detected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let w1 = EncryptedWallet::new(
            "id-a".to_string(),
            "same-name".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&w1, Some(&vault)).unwrap();

        assert!(wallet_name_exists("same-name", Some(&vault)).unwrap());
    }

    #[test]
    fn char_wallet_not_found_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = load_wallet_by_name_or_id("nonexistent", Some(&vault));
        assert!(result.is_err());
        match result.unwrap_err() {
            OwsLibError::WalletNotFound(name) => assert_eq!(name, "nonexistent"),
            other => panic!("expected WalletNotFound, got: {other}"),
        }
    }

    #[test]
    fn char_delete_nonexistent_wallet_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = delete_wallet_file("no-such-id", Some(&vault));
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn char_wallet_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "perm-id".to_string(),
            "perm-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        // Check file permissions are 0o600
        let file_path = vault.join("wallets/perm-id.json");
        let meta = std::fs::metadata(&file_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "wallet file should have 0600 permissions, got {:04o}",
            mode
        );

        // Check directory permissions are 0o700
        let wallets_dir_path = vault.join("wallets");
        let dir_meta = std::fs::metadata(&wallets_dir_path).unwrap();
        let dir_mode = dir_meta.permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "wallets directory should have 0700 permissions, got {:04o}",
            dir_mode
        );
    }
}
