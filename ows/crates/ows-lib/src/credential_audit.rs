//! Audit records for credential operations, appended to `<vault>/logs/audit.jsonl` in the format
//! of the CLI's wallet records. They are written here rather than in the CLI so that a binding
//! records a credential operation exactly as the CLI does. A record that cannot be written never
//! fails the operation.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use ows_core::policy::TypedDataContext;
use ows_core::{ApiKeyFile, Credential, OwsError};
use serde::Serialize;

use crate::error::OwsLibError;
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

/// How the caller proved its authority for a signing. The token itself is never recorded.
pub(crate) enum Actor {
    Owner,
    ApiKey,
}

impl Actor {
    fn as_str(&self) -> &'static str {
        match self {
            Actor::Owner => "owner",
            Actor::ApiKey => "api_key",
        }
    }
}

/// The verdict on a signing. A policy denial is recorded under the same operation as an allowed
/// signing, so a refused attempt is a record rather than an absence.
pub(crate) enum Outcome<'a> {
    Allowed,
    Denied { policy_id: &'a str, reason: &'a str },
}

/// Longest policy-supplied `reason` a record carries. It is an executable policy's own output.
const MAX_REASON: usize = 500;

impl Outcome<'_> {
    /// The verdict `err` carries, or `None` when the operation failed for any other reason.
    pub(crate) fn denial(err: &OwsLibError) -> Option<Outcome<'_>> {
        match err {
            OwsLibError::Core(OwsError::PolicyDenied { policy_id, reason }) => {
                Some(Outcome::Denied { policy_id, reason })
            }
            _ => None,
        }
    }

    fn describe(&self) -> String {
        match self {
            Outcome::Allowed => "outcome=allowed".to_string(),
            Outcome::Denied { policy_id, reason } => {
                let reason = if reason.len() > MAX_REASON {
                    format!("{}…", &reason[..reason.floor_char_boundary(MAX_REASON)])
                } else {
                    (*reason).to_string()
                };
                format!("outcome=denied, policy={policy_id}, reason={reason}")
            }
        }
    }
}

/// A signature is a bearer artifact, so each one is traced, with the account and the circuit the
/// request names, and so is each policy denial.
pub(crate) fn signed(
    credential_id: &str,
    chain_id: &str,
    request: &TypedDataContext,
    actor: &Actor,
    outcome: &Outcome,
    vault_path: Option<&Path>,
) {
    append(
        "credential_signed",
        Some(chain_id),
        format!(
            "credential_id={credential_id}, verifying_contract={}, primary_type={}, actor={}, {}",
            request.verifying_contract.as_deref().unwrap_or("none"),
            request.primary_type,
            actor.as_str(),
            outcome.describe(),
        ),
        vault_path,
    );
}

/// Each credential an API key is granted when it is created, or loses when it is revoked, with the
/// policies that gate it.
pub(crate) fn api_key_credentials(operation: &str, key: &ApiKeyFile, vault_path: Option<&Path>) {
    let policies = if key.policy_ids.is_empty() {
        "none".to_string()
    } else {
        key.policy_ids.join(" ")
    };
    for credential_id in &key.credential_ids {
        append(
            operation,
            None,
            format!(
                "key_id={}, name={}, credential_id={credential_id}, policies={policies}",
                key.id, key.name
            ),
            vault_path,
        );
    }
}
