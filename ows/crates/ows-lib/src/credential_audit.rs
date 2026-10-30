//! Audit records for credential operations, appended to `<vault>/logs/audit.jsonl` in the format
//! of the CLI's wallet records. They are written here rather than in the CLI so that a binding
//! records a credential operation exactly as the CLI does. A record that cannot be written never
//! fails the operation.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use ows_core::policy::TypedDataContext;
use ows_core::Credential;
use serde::Serialize;

use crate::types::CredentialInfo;
use crate::vault;

/// One line of the log. A credential belongs to the vault rather than to a wallet, so its records
/// carry no `wallet_id`.
#[derive(Serialize)]
struct Entry<'a> {
    timestamp: String,
    operation: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_id: Option<&'a str>,
    details: String,
}

fn append(operation: &str, chain_id: Option<&str>, details: String, vault_path: Option<&Path>) {
    let log_dir = vault::resolve_vault_path(vault_path).join("logs");
    let log_path = log_dir.join("audit.jsonl");

    let _ = fs::create_dir_all(&log_dir);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700));
    }

    let entry = Entry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        operation,
        chain_id,
        details,
    };
    if let Ok(json) = serde_json::to_string(&entry) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = writeln!(file, "{json}");

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
            }
        }
    }
}

fn describe(info: &CredentialInfo) -> String {
    format!(
        "credential_id={}, name={}, chain={}, scheme={}, public_key={}",
        info.id, info.name, info.chain, info.scheme, info.public_key
    )
}

pub(crate) fn created(info: &CredentialInfo, vault_path: Option<&Path>) {
    append("credential_created", None, describe(info), vault_path);
}

/// Kept apart from creation because an imported key may live elsewhere too.
pub(crate) fn imported(info: &CredentialInfo, vault_path: Option<&Path>) {
    append("credential_imported", None, describe(info), vault_path);
}

pub(crate) fn deleted(credential: &Credential, vault_path: Option<&Path>) {
    append(
        "credential_deleted",
        None,
        format!("credential_id={}, name={}", credential.id, credential.name),
        vault_path,
    );
}

/// A signature is a bearer artifact, so each one is traced, with the account and the circuit the
/// request names.
pub(crate) fn signed(
    credential_id: &str,
    chain_id: &str,
    request: &TypedDataContext,
    vault_path: Option<&Path>,
) {
    append(
        "credential_signed",
        Some(chain_id),
        format!(
            "credential_id={credential_id}, verifying_contract={}, primary_type={}, actor=owner, outcome=allowed",
            request.verifying_contract.as_deref().unwrap_or("none"),
            request.primary_type,
        ),
        vault_path,
    );
}
