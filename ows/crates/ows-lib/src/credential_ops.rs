//! Create, import, list and delete credentials. Nothing here names a chain: the chain
//! and scheme select a [`CredentialScheme`] in `ows-signer`.

use std::path::Path;
use std::str::FromStr;

use ows_core::{ChainType, Credential, CredentialOrigin, PolicyRequestType};
use ows_signer::{
    credential_scheme, decrypt, encrypt, CredentialKey, CredentialScheme, CryptoEnvelope,
    SecretBytes,
};
use zeroize::Zeroizing;

use crate::credential_audit::{self, Actor, Outcome};
use crate::credential_store;
use crate::error::OwsLibError;
use crate::key_ops;
use crate::key_store::{self, TOKEN_PREFIX};
use crate::types::{CredentialInfo, CredentialSignature};

/// Accepts a chain name or bare namespace as well as a full chain id. A chain it does not know is
/// not echoed back, since a caller that misplaces arguments could pass a secret in its slot.
fn parse_credential_chain(chain: &str) -> Result<ChainType, OwsLibError> {
    if let Ok(chain_type) = ChainType::from_str(chain) {
        return Ok(chain_type);
    }
    if let Some(chain_type) = ChainType::from_namespace(chain) {
        return Ok(chain_type);
    }
    ows_core::parse_chain(chain)
        .map(|c| c.chain_type)
        .map_err(|_| {
            OwsLibError::InvalidInput(
                "unknown chain: give a chain name, a namespace or a CAIP-2 chain id".into(),
            )
        })
}

fn credential_to_info(credential: &Credential) -> CredentialInfo {
    CredentialInfo {
        id: credential.id.clone(),
        name: credential.name.clone(),
        chain: credential.chain,
        scheme: credential.scheme.clone(),
        public_key: credential.public_key.clone(),
        origin: credential.origin,
        created_at: credential.created_at.clone(),
    }
}

fn new_id() -> Result<String, OwsLibError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| {
        OwsLibError::InvalidInput(format!("failed to generate a credential id: {e}"))
    })?;
    Ok(uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string())
}

fn store_credential(
    name: &str,
    chain: ChainType,
    scheme: &dyn CredentialScheme,
    key: CredentialKey,
    origin: CredentialOrigin,
    passphrase: &str,
    vault_path: Option<&Path>,
) -> Result<CredentialInfo, OwsLibError> {
    let crypto = serde_json::to_value(encrypt(key.secret.expose(), passphrase)?)?;
    let credential = Credential::new(
        new_id()?,
        name.to_string(),
        chain,
        scheme.name().to_string(),
        key.public_key,
        origin,
        crypto,
    );
    credential_store::save_credential_file(&credential, vault_path)?;
    Ok(credential_to_info(&credential))
}

/// The passphrase a new credential is sealed under. Unlike a wallet's it may not be empty, and an
/// agent token is not a passphrase: sealing under it would make the credential unopenable on the
/// owner path.
fn sealing_passphrase(passphrase: Option<&str>) -> Result<&str, OwsLibError> {
    match passphrase.unwrap_or("") {
        "" => Err(OwsLibError::InvalidInput(
            "a credential needs a passphrase: under an empty one, anyone who can run ows on this \
             vault signs as its owner, past every token policy"
                .into(),
        )),
        token if token.starts_with(crate::key_store::TOKEN_PREFIX) => {
            Err(OwsLibError::InvalidInput(
                "an agent token cannot seal a credential; use the owner passphrase".into(),
            ))
        }
        passphrase => Ok(passphrase),
    }
}

/// Generate a new credential key and store it encrypted under `passphrase`.
pub fn create_credential(
    name: &str,
    chain: &str,
    scheme: Option<&str>,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<CredentialInfo, OwsLibError> {
    let passphrase = sealing_passphrase(passphrase)?;
    let chain = parse_credential_chain(chain)?;
    let scheme = credential_scheme(chain, scheme)?;

    if credential_store::credential_name_exists(name, vault_path)? {
        return Err(OwsLibError::CredentialNameExists(name.to_string()));
    }

    let key = scheme.generate()?;
    let info = store_credential(
        name,
        chain,
        scheme.as_ref(),
        key,
        CredentialOrigin::Generated,
        passphrase,
        vault_path,
    )?;
    credential_audit::created(&info, vault_path);
    Ok(info)
}

/// Store an existing credential key, given as hex in the scheme's import format.
pub fn import_credential(
    name: &str,
    chain: &str,
    scheme: Option<&str>,
    secret_hex: &str,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<CredentialInfo, OwsLibError> {
    let passphrase = sealing_passphrase(passphrase)?;
    let chain = parse_credential_chain(chain)?;
    let scheme = credential_scheme(chain, scheme)?;

    if credential_store::credential_name_exists(name, vault_path)? {
        return Err(OwsLibError::CredentialNameExists(name.to_string()));
    }

    let trimmed = secret_hex.strip_prefix("0x").unwrap_or(secret_hex);
    // The decoder's error names the offending character, which is part of the secret.
    let secret = hex::decode(trimmed)
        .map(Zeroizing::new)
        .map_err(|_| OwsLibError::InvalidInput("the secret is not valid hex".into()))?;
    let key = scheme.import(&secret)?;
    let info = store_credential(
        name,
        chain,
        scheme.as_ref(),
        key,
        CredentialOrigin::Imported,
        passphrase,
        vault_path,
    )?;
    credential_audit::imported(&info, vault_path);
    Ok(info)
}

/// All credentials in the vault, newest first.
pub fn list_credentials(vault_path: Option<&Path>) -> Result<Vec<CredentialInfo>, OwsLibError> {
    Ok(credential_store::list_credential_files(vault_path)?
        .iter()
        .map(credential_to_info)
        .collect())
}

/// Look up a credential by ID or name.
pub fn get_credential(
    name_or_id: &str,
    vault_path: Option<&Path>,
) -> Result<CredentialInfo, OwsLibError> {
    credential_store::load_credential_by_name_or_id(name_or_id, vault_path)
        .map(|c| credential_to_info(&c))
}

/// Delete a credential by ID or name.
///
/// Agent tokens lose their access too: the id leaves every token file's scope and the token's
/// encrypted copy of the secret is dropped.
pub fn delete_credential(name_or_id: &str, vault_path: Option<&Path>) -> Result<(), OwsLibError> {
    let credential = credential_store::load_credential_by_name_or_id(name_or_id, vault_path)?;
    // Listing the keys would create `keys/` in a vault that has never held one.
    if crate::vault::resolve_vault_path(vault_path)
        .join("keys")
        .is_dir()
    {
        for mut key in key_store::list_api_keys(vault_path)? {
            let held = key.credential_ids.len() + key.credential_secrets.len();
            key.credential_ids.retain(|id| id != &credential.id);
            key.credential_secrets.remove(&credential.id);
            if key.credential_ids.len() + key.credential_secrets.len() != held {
                key_store::save_api_key(&key, vault_path)?;
            }
        }
    }
    credential_store::delete_credential_file(&credential.id, vault_path)?;
    credential_audit::deleted(&credential, vault_path);
    Ok(())
}

/// A credential's encrypted key is not bound to the rest of its file, so whoever can write the
/// vault could swap two credentials' keys. The decrypted key must be the one behind the public key
/// the file names.
pub(crate) fn check_key(credential: &Credential, secret: &SecretBytes) -> Result<(), OwsLibError> {
    let scheme = credential_scheme(credential.chain, Some(&credential.scheme))?;
    if scheme.import(secret.expose())?.public_key != credential.public_key {
        return Err(OwsLibError::InvalidInput(format!(
            "credential '{}' holds a key that does not match its public key",
            credential.name
        )));
    }
    Ok(())
}

/// Sign an authorisation request with a credential's key.
///
/// A passphrase that starts with `ows_key_` is an agent token: the token must hold the
/// credential, and every policy on it runs over the request before the token's copy of the key is
/// decrypted. Anything else is the owner's passphrase.
///
/// The chain and the request are checked before the key is decrypted, so a request
/// for another chain or one the scheme rejects never reaches the passphrase.
pub fn sign_with_credential(
    name_or_id: &str,
    chain: &str,
    request: &str,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<CredentialSignature, OwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let agent = if passphrase.starts_with(TOKEN_PREFIX) {
        Some(key_ops::load_authorized_credential(
            passphrase, name_or_id, vault_path,
        )?)
    } else {
        None
    };
    let credential = match &agent {
        Some((_, credential)) => credential.clone(),
        None => credential_store::load_credential_by_name_or_id(name_or_id, vault_path)?,
    };

    let request_chain = parse_credential_chain(chain)?;
    if request_chain != credential.chain {
        return Err(OwsLibError::InvalidInput(format!(
            "credential '{}' is for {}, not {}",
            credential.name, credential.chain, request_chain
        )));
    }

    let scheme = credential_scheme(credential.chain, Some(&credential.scheme))?;
    let described = scheme.describe(request)?;

    let actor = if agent.is_some() {
        Actor::ApiKey
    } else {
        Actor::Owner
    };
    let secret = match &agent {
        Some((key_file, _)) => {
            let policy_chain = ows_core::parse_chain(chain)
                .unwrap_or_else(|_| ows_core::default_chain_for_type(credential.chain));
            if let Err(e) = key_ops::enforce_policies(
                key_file,
                "",
                Some(&credential.id),
                &policy_chain,
                PolicyRequestType::SignTypedData,
                None,
                Some(described.clone()),
                vault_path,
            ) {
                if let Some(denied) = Outcome::denial(&e) {
                    credential_audit::signed(
                        &credential.id,
                        chain,
                        &described,
                        &actor,
                        &denied,
                        vault_path,
                    );
                }
                return Err(e);
            }
            key_ops::decrypt_credential_from_api_key(key_file, &credential, passphrase)?
        }
        None => {
            let envelope: CryptoEnvelope = serde_json::from_value(credential.crypto.clone())?;
            decrypt(&envelope, passphrase)?
        }
    };
    check_key(&credential, &secret)?;
    let signature = scheme.sign(secret.expose(), request)?;
    let fields = scheme.signature_fields(&credential.public_key, &signature)?;
    credential_audit::signed(
        &credential.id,
        chain,
        &described,
        &actor,
        &Outcome::Allowed,
        vault_path,
    );

    Ok(CredentialSignature {
        signature: hex::encode(signature),
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault;
    use ows_core::{EncryptedWallet, KeyType};
    use ows_signer::{decrypt, CryptoEnvelope};

    const PASS: &str = "hunter2";

    #[test]
    fn create_then_list_shows_the_public_key_and_origin() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        assert_eq!(made.origin, CredentialOrigin::Generated);
        assert_eq!(made.chain, ChainType::Midnight);
        assert_eq!(made.scheme, "jubjub");

        let listed = list_credentials(v).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].public_key, made.public_key);
        assert_eq!(listed[0].origin, CredentialOrigin::Generated);
        assert_eq!(get_credential("device", v).unwrap().id, made.id);

        let file = credential_store::load_credential_by_name_or_id("device", v).unwrap();
        let envelope: CryptoEnvelope = serde_json::from_value(file.crypto).unwrap();
        let secret = decrypt(&envelope, PASS).unwrap();
        let scheme = credential_scheme(ChainType::Midnight, None).unwrap();
        assert_eq!(
            scheme.import(secret.expose()).unwrap().public_key,
            made.public_key
        );
    }

    #[test]
    fn a_full_chain_id_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let made = create_credential("d", "midnight:stagenet", None, Some(PASS), Some(dir.path()));
        assert_eq!(made.unwrap().chain, ChainType::Midnight);
    }

    #[test]
    fn import_is_labelled_imported() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let source = create_credential("source", "midnight", None, Some(PASS), v).unwrap();
        let file = credential_store::load_credential_by_name_or_id("source", v).unwrap();
        let envelope: CryptoEnvelope = serde_json::from_value(file.crypto).unwrap();
        let secret_hex = hex::encode(decrypt(&envelope, PASS).unwrap().expose());

        let imported = import_credential(
            "copy",
            "midnight",
            Some("jubjub"),
            &format!("0x{secret_hex}"),
            Some(PASS),
            v,
        )
        .unwrap();
        assert_eq!(imported.origin, CredentialOrigin::Imported);
        assert_eq!(imported.public_key, source.public_key);
    }

    #[test]
    fn import_refuses_a_bad_secret() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        assert!(import_credential("a", "midnight", None, "zz", Some(PASS), v).is_err());
        assert!(import_credential("a", "midnight", None, &"00".repeat(32), Some(PASS), v).is_err());
        assert!(list_credentials(v).unwrap().is_empty());
    }

    #[test]
    fn create_and_import_refuse_an_empty_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        for passphrase in [None, Some("")] {
            for refused in [
                create_credential("device", "midnight", None, passphrase, v),
                import_credential("copy", "midnight", None, &"01".repeat(32), passphrase, v),
            ] {
                assert!(
                    matches!(&refused, Err(OwsLibError::InvalidInput(m)) if m.contains("needs a passphrase")),
                    "{refused:?}"
                );
            }
        }
        assert!(list_credentials(v).unwrap().is_empty());
    }

    #[test]
    fn errors_do_not_echo_what_may_be_a_secret() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let secret = "0123456789abcdef0123456789abcdef";
        let refusals = [
            create_credential("d", "midnight", Some(secret), Some(PASS), v),
            create_credential("d", secret, None, Some(PASS), v),
            import_credential(
                "d",
                "midnight",
                Some(secret),
                &"01".repeat(32),
                Some(PASS),
                v,
            ),
            import_credential("d", secret, None, &"01".repeat(32), Some(PASS), v),
        ];
        for refused in refusals {
            let message = refused.unwrap_err().to_string();
            assert!(!message.contains(secret), "{message}");
        }
        let bad_hex = format!("{}Z", "0".repeat(63));
        let message = import_credential("d", "midnight", None, &bad_hex, Some(PASS), v)
            .unwrap_err()
            .to_string();
        assert!(
            !message.contains('Z') && !message.contains("63"),
            "{message}"
        );
    }

    #[test]
    fn create_refuses_an_agent_token_as_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let token = format!("{}deadbeef", crate::key_store::TOKEN_PREFIX);
        let err = create_credential("device", "midnight", None, Some(&token), v).unwrap_err();
        assert!(matches!(err, OwsLibError::InvalidInput(m) if m.contains("agent token")));
        assert!(list_credentials(v).unwrap().is_empty());
    }

    #[test]
    fn import_refuses_an_agent_token_as_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let token = format!("{}deadbeef", crate::key_store::TOKEN_PREFIX);
        let err = import_credential("copy", "midnight", None, &"01".repeat(32), Some(&token), v)
            .unwrap_err();
        assert!(matches!(err, OwsLibError::InvalidInput(m) if m.contains("agent token")));
        assert!(list_credentials(v).unwrap().is_empty());
    }

    #[test]
    fn a_taken_credential_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        assert!(matches!(
            create_credential("device", "midnight", None, Some(PASS), v),
            Err(OwsLibError::CredentialNameExists(_))
        ));
        assert!(matches!(
            import_credential("device", "midnight", None, &"01".repeat(32), Some(PASS), v),
            Err(OwsLibError::CredentialNameExists(_))
        ));
    }

    #[test]
    fn a_wallet_and_a_credential_may_share_a_name() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let wallet = EncryptedWallet::new(
            "wallet-id".to_string(),
            "shared".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        vault::save_encrypted_wallet(&wallet, v).unwrap();
        let made = create_credential("shared", "midnight", None, Some(PASS), v).unwrap();
        assert_eq!(get_credential("shared", v).unwrap().id, made.id);
        assert_eq!(
            vault::load_wallet_by_name_or_id("shared", v).unwrap().id,
            "wallet-id"
        );
    }

    #[test]
    fn delete_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        delete_credential("device", v).unwrap();
        assert!(list_credentials(v).unwrap().is_empty());
        assert!(matches!(
            delete_credential("device", v),
            Err(OwsLibError::CredentialNotFound(_))
        ));
    }

    #[test]
    fn an_unsupported_chain_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        for chain in ["evm", "eip155:1", "solana"] {
            assert!(matches!(
                create_credential("x", chain, None, Some(PASS), v),
                Err(OwsLibError::Signer(_))
            ));
        }
        assert!(matches!(
            create_credential("x", "nonsense", None, Some(PASS), v),
            Err(OwsLibError::InvalidInput(_))
        ));
        assert!(list_credentials(v).unwrap().is_empty());
    }

    fn withdraw_request() -> String {
        serde_json::json!({
            "scheme": "midnight:account:auth:v1",
            "account": "a19612afc371b1a4d2fc2410377da895ff7ca406e74449b75dcc32a2b6df7964",
            "circuit": "withdraw_unshielded",
            "args": [
                {"type": "Bytes<32>", "value": "5cd36fe5ed159246257b476bb67bc8266290581ef3844fcabd7c134b3f8b03ea"},
                {"type": "Uint<128>", "value": "3000000"},
                {"type": "UserAddress", "value": "0xb0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9e00"}
            ],
            "witnesses": [],
            "authNonce": "3"
        })
        .to_string()
    }

    #[test]
    fn owner_signature_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let request = withdraw_request();
        let signed =
            sign_with_credential("device", "midnight:stagenet", &request, Some(PASS), v).unwrap();
        let sig = hex::decode(&signed.signature).unwrap();
        assert_eq!(sig.len(), 104);
        let scheme = credential_scheme(ChainType::Midnight, None).unwrap();
        scheme.verify(&made.public_key, &request, &sig).unwrap();
        assert_eq!(
            signed.fields,
            scheme.signature_fields(&made.public_key, &sig).unwrap()
        );
        assert_eq!(signed.fields["pk"], made.public_key.as_str());
        let json = signed.to_json();
        assert_eq!(json["signature"], signed.signature.as_str());
        assert_eq!(json.len(), signed.fields.len() + 1);
    }

    #[test]
    fn another_chain_is_refused_before_decrypting() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let err = sign_with_credential("device", "evm", &withdraw_request(), Some("wrong"), v)
            .unwrap_err();
        assert!(matches!(err, OwsLibError::InvalidInput(_)), "{err:?}");
    }

    #[test]
    fn evm_typed_data_is_refused_before_decrypting() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let evm = serde_json::json!({
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}],
                "Mail": [{"name": "contents", "type": "string"}]
            },
            "primaryType": "Mail",
            "domain": {"name": "Ether Mail"},
            "message": {"contents": "hi"}
        })
        .to_string();
        let err = sign_with_credential("device", "midnight", &evm, Some("wrong"), v).unwrap_err();
        assert!(matches!(err, OwsLibError::Signer(_)), "{err:?}");
    }

    #[test]
    fn a_wrong_passphrase_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let err = sign_with_credential("device", "midnight", &withdraw_request(), Some("nope"), v)
            .unwrap_err();
        assert!(matches!(err, OwsLibError::Crypto(_)), "{err:?}");
    }

    #[test]
    fn a_key_swapped_in_from_another_credential_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        create_credential("other", "midnight", None, Some(PASS), v).unwrap();
        let mut device = credential_store::load_credential_by_name_or_id("device", v).unwrap();
        let other = credential_store::load_credential_by_name_or_id("other", v).unwrap();
        device.crypto = other.crypto;
        credential_store::save_credential_file(&device, v).unwrap();

        let err = sign_with_credential("device", "midnight", &withdraw_request(), Some(PASS), v)
            .unwrap_err();
        assert!(
            matches!(&err, OwsLibError::InvalidInput(m) if m.contains("does not match its public key")),
            "{err:?}"
        );
    }

    #[test]
    fn an_owner_signature_is_audited_and_a_failed_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        sign_with_credential(
            "device",
            "midnight:stagenet",
            &withdraw_request(),
            Some(PASS),
            v,
        )
        .unwrap();
        sign_with_credential("device", "midnight", &withdraw_request(), Some("nope"), v)
            .unwrap_err();

        let log = audit_log(dir.path());
        assert_eq!(log.len(), 2, "{log:?}");
        assert_eq!(
            log[1],
            (
                "credential_signed".to_string(),
                format!(
                    "credential_id={}, verifying_contract=a19612afc371b1a4d2fc2410377da895ff7ca406e74449b75dcc32a2b6df7964, primary_type=withdraw_unshielded, actor=owner, outcome=allowed",
                    made.id
                )
            )
        );
        let last = std::fs::read_to_string(dir.path().join("logs/audit.jsonl")).unwrap();
        let last: serde_json::Value = serde_json::from_str(last.lines().last().unwrap()).unwrap();
        assert_eq!(last["chain_id"], "midnight:stagenet");
    }

    const CONTRACT: &str = "a19612afc371b1a4d2fc2410377da895ff7ca406e74449b75dcc32a2b6df7964";

    fn contract_policy(vault: &Path, id: &str, contract: &str) -> String {
        let policy = ows_core::Policy {
            id: id.to_string(),
            name: id.to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules: vec![ows_core::PolicyRule::AllowedTypedDataContracts {
                contracts: vec![contract.to_string()],
            }],
            executable: None,
            config: None,
            action: ows_core::PolicyAction::Deny,
        };
        crate::policy_store::save_policy(&policy, Some(vault)).unwrap();
        policy.id
    }

    fn agent(
        vault: &Path,
        credentials: &[String],
        policies: &[String],
        expires_at: Option<&str>,
    ) -> String {
        crate::key_ops::create_api_key_with_credentials(
            "agent",
            &[],
            credentials,
            policies,
            PASS,
            expires_at,
            Some(vault),
        )
        .unwrap()
        .0
    }

    #[test]
    fn agent_signs_for_an_allowed_contract() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let policy = contract_policy(dir.path(), "allow", &CONTRACT.to_uppercase());
        let token = agent(dir.path(), &[made.id.clone()], &[policy], None);
        let request = withdraw_request();
        let signed = sign_with_credential("device", "midnight", &request, Some(&token), v).unwrap();
        assert_eq!(signed.fields["pk"], made.public_key.as_str());
        credential_scheme(ChainType::Midnight, None)
            .unwrap()
            .verify(
                &made.public_key,
                &request,
                &hex::decode(&signed.signature).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn agent_is_denied_for_another_contract() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let policy = contract_policy(dir.path(), "other-only", &"ab".repeat(32));
        let token = agent(dir.path(), &[made.id], &[policy], None);
        let err = sign_with_credential("device", "midnight", &withdraw_request(), Some(&token), v)
            .unwrap_err();
        match err {
            OwsLibError::Core(ows_core::OwsError::PolicyDenied { policy_id, .. }) => {
                assert_eq!(policy_id, "other-only")
            }
            other => panic!("{other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn executable_policy_sees_credential_id_and_empty_wallet_id() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let seen = dir.path().join("seen.json");
        let script = dir.path().join("record.py");
        std::fs::write(
            &script,
            format!(
                "#!/usr/bin/env python3\nimport sys\nopen({:?}, 'w').write(sys.stdin.read())\nprint('{{\"allow\": true}}')\n",
                seen.display().to_string()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        crate::policy_store::save_policy(
            &ows_core::Policy {
                id: "record".to_string(),
                name: "record".to_string(),
                version: 1,
                created_at: "2026-03-22T10:00:00Z".to_string(),
                rules: vec![],
                executable: Some(script.display().to_string()),
                config: None,
                action: ows_core::PolicyAction::Deny,
            },
            v,
        )
        .unwrap();
        let token = agent(
            dir.path(),
            &[made.id.clone()],
            &["record".to_string()],
            None,
        );
        sign_with_credential("device", "midnight", &withdraw_request(), Some(&token), v).unwrap();

        let payload: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&seen).unwrap()).unwrap();
        assert_eq!(payload["credential_id"], made.id.as_str());
        assert_eq!(payload["wallet_id"], "");
        assert_eq!(payload["request_type"], "sign_typed_data");
        assert_eq!(payload["typed_data"]["verifying_contract"], CONTRACT);
        assert_eq!(payload["typed_data"]["primary_type"], "withdraw_unshielded");
        assert_eq!(
            payload["typed_data"]["domain_name"],
            "midnight:account:auth:v1"
        );
        assert_eq!(payload["typed_data"]["raw_json"], withdraw_request());
        assert!(payload.get("transaction").is_none());
    }

    #[test]
    fn a_token_without_the_credential_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let other = create_credential("other", "midnight", None, Some(PASS), v).unwrap();
        let token = agent(dir.path(), &[other.id], &[], None);
        let err = sign_with_credential("device", "midnight", &withdraw_request(), Some(&token), v)
            .unwrap_err();
        assert!(matches!(err, OwsLibError::InvalidInput(_)), "{err:?}");
    }

    #[test]
    fn an_expired_token_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let token = agent(dir.path(), &[made.id], &[], Some("2020-01-01T00:00:00Z"));
        let err = sign_with_credential("device", "midnight", &withdraw_request(), Some(&token), v)
            .unwrap_err();
        assert!(
            matches!(
                err,
                OwsLibError::Core(ows_core::OwsError::ApiKeyExpired { .. })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn an_old_token_file_loads() {
        let old = serde_json::json!({
            "id": "k", "name": "old", "token_hash": "h", "created_at": "2026-03-22T10:30:00Z",
            "wallet_ids": [], "policy_ids": [], "wallet_secrets": {}
        });
        let key: ows_core::ApiKeyFile = serde_json::from_value(old).unwrap();
        assert!(key.credential_ids.is_empty() && key.credential_secrets.is_empty());
        let json = serde_json::to_string(&key).unwrap();
        assert!(!json.contains("credential"), "{json}");
    }

    #[test]
    fn delete_purges_token_copies() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let gone = create_credential("gone", "midnight", None, Some(PASS), v).unwrap();
        let kept = create_credential("kept", "midnight", None, Some(PASS), v).unwrap();
        let token = agent(dir.path(), &[gone.id.clone(), kept.id.clone()], &[], None);
        delete_credential("gone", v).unwrap();

        let keys = crate::key_store::list_api_keys(v).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].credential_ids, vec![kept.id.clone()]);
        assert!(!keys[0].credential_secrets.contains_key(&gone.id));
        assert!(keys[0].credential_secrets.contains_key(&kept.id));
        sign_with_credential("kept", "midnight", &withdraw_request(), Some(&token), v).unwrap();
    }

    #[test]
    fn token_creation_refuses_a_swapped_key() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        create_credential("other", "midnight", None, Some(PASS), v).unwrap();
        let mut device = credential_store::load_credential_by_name_or_id("device", v).unwrap();
        device.crypto = credential_store::load_credential_by_name_or_id("other", v)
            .unwrap()
            .crypto;
        credential_store::save_credential_file(&device, v).unwrap();

        let err = crate::key_ops::create_api_key_with_credentials(
            "agent",
            &[],
            &[made.id],
            &[],
            PASS,
            None,
            v,
        )
        .unwrap_err();
        assert!(
            matches!(&err, OwsLibError::InvalidInput(m) if m.contains("does not match its public key")),
            "{err:?}"
        );
    }

    #[test]
    fn agent_signing_refuses_a_swapped_token_copy() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let device = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let other = create_credential("other", "midnight", None, Some(PASS), v).unwrap();
        let token = agent(
            dir.path(),
            &[device.id.clone(), other.id.clone()],
            &[],
            None,
        );
        let mut key = crate::key_store::list_api_keys(v).unwrap().remove(0);
        let other_copy = key.credential_secrets[&other.id].clone();
        key.credential_secrets.insert(device.id, other_copy);
        crate::key_store::save_api_key(&key, v).unwrap();

        let err = sign_with_credential("device", "midnight", &withdraw_request(), Some(&token), v)
            .unwrap_err();
        assert!(
            matches!(&err, OwsLibError::InvalidInput(m) if m.contains("does not match its public key")),
            "{err:?}"
        );
    }

    #[test]
    fn an_unknown_token_is_refused_before_the_name_is_looked_up() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let token = format!("{TOKEN_PREFIX}{}", "00".repeat(32));
        for name in ["no-such-credential", "device"] {
            if name == "device" {
                create_credential(name, "midnight", None, Some(PASS), v).unwrap();
            }
            let err = sign_with_credential(name, "midnight", &withdraw_request(), Some(&token), v)
                .unwrap_err();
            assert!(
                matches!(err, OwsLibError::Core(ows_core::OwsError::ApiKeyNotFound)),
                "{name}: {err:?}"
            );
        }
    }

    #[test]
    fn delete_does_not_create_a_keys_directory() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        delete_credential("device", v).unwrap();
        assert!(!dir.path().join("keys").exists());
    }

    #[test]
    fn agent_signatures_and_denials_are_audited() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let policy = contract_policy(dir.path(), "allow", CONTRACT);
        let token = agent(dir.path(), std::slice::from_ref(&made.id), &[policy], None);
        sign_with_credential("device", "midnight", &withdraw_request(), Some(&token), v).unwrap();
        let other = withdraw_request().replace(CONTRACT, &"ab".repeat(32));
        sign_with_credential("device", "midnight", &other, Some(&token), v).unwrap_err();

        let signed: Vec<String> = audit_log(dir.path())
            .into_iter()
            .filter(|(op, _)| op == "credential_signed")
            .map(|(_, details)| details)
            .collect();
        let head = |contract: &str| {
            format!(
                "credential_id={}, verifying_contract={contract}, primary_type=withdraw_unshielded, actor=api_key, ",
                made.id
            )
        };
        assert_eq!(signed.len(), 2, "{signed:?}");
        assert_eq!(signed[0], format!("{}outcome=allowed", head(CONTRACT)));
        assert!(
            signed[1].starts_with(&format!(
                "{}outcome=denied, policy=allow, reason=",
                head(&"ab".repeat(32))
            )),
            "{}",
            signed[1]
        );
    }

    #[test]
    fn granting_and_revoking_a_credential_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let policy = contract_policy(dir.path(), "allow", CONTRACT);
        agent(dir.path(), std::slice::from_ref(&made.id), &[policy], None);
        let key = crate::key_store::list_api_keys(v).unwrap().remove(0);
        crate::key_ops::revoke_api_key(&key.id, v).unwrap();
        assert!(crate::key_store::list_api_keys(v).unwrap().is_empty());

        let details = format!(
            "key_id={}, name=agent, credential_id={}, policies=allow",
            key.id, made.id
        );
        let log = audit_log(dir.path());
        assert_eq!(
            log[1..],
            [
                ("create_api_key".to_string(), details.clone()),
                ("revoke_api_key".to_string(), details)
            ]
        );
    }

    #[test]
    fn one_token_holds_a_wallet_under_the_empty_passphrase_and_a_credential() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let wallet = crate::ops::create_wallet("pay", None, None, v).unwrap();
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let wallets = std::slice::from_ref(&wallet.id);
        let credentials = std::slice::from_ref(&made.id);

        assert!(matches!(
            crate::key_ops::create_api_key_with_credentials(
                "agent",
                wallets,
                credentials,
                &[],
                "wrong",
                None,
                v
            ),
            Err(OwsLibError::Crypto(_))
        ));
        let (token, _) = crate::key_ops::create_api_key_with_credentials(
            "agent",
            wallets,
            credentials,
            &[],
            PASS,
            None,
            v,
        )
        .unwrap();

        let chain = ows_core::parse_chain("ethereum").unwrap();
        crate::key_ops::sign_message_with_api_key(&token, "pay", &chain, b"hi", None, None, v)
            .unwrap();
        let request = withdraw_request();
        let signed = sign_with_credential("device", "midnight", &request, Some(&token), v).unwrap();
        credential_scheme(ChainType::Midnight, None)
            .unwrap()
            .verify(
                &made.public_key,
                &request,
                &hex::decode(&signed.signature).unwrap(),
            )
            .unwrap();

        // A key for wallets alone still opens each one under the given passphrase only.
        assert!(matches!(
            crate::key_ops::create_api_key("wallet-only", wallets, &[], PASS, None, v),
            Err(OwsLibError::Crypto(_))
        ));
    }

    /// `(operation, details)` of each line of the vault's audit log.
    fn audit_log(vault: &Path) -> Vec<(String, String)> {
        let log = std::fs::read_to_string(vault.join("logs/audit.jsonl")).unwrap_or_default();
        log.lines()
            .map(|line| {
                let entry: serde_json::Value = serde_json::from_str(line).unwrap();
                assert!(entry.get("wallet_id").is_none(), "{line}");
                (
                    entry["operation"].as_str().unwrap().to_string(),
                    entry["details"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn each_change_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let v = Some(dir.path());
        let made = create_credential("device", "midnight", None, Some(PASS), v).unwrap();
        let copy =
            import_credential("copy", "midnight", None, &"01".repeat(32), Some(PASS), v).unwrap();
        delete_credential("copy", v).unwrap();
        create_credential("device", "midnight", None, Some(PASS), v).unwrap_err();

        let log = audit_log(dir.path());
        let operations: Vec<&str> = log.iter().map(|(op, _)| op.as_str()).collect();
        assert_eq!(
            operations,
            [
                "credential_created",
                "credential_imported",
                "credential_deleted"
            ]
        );
        assert_eq!(
            log[0].1,
            format!(
                "credential_id={}, name=device, chain=midnight, scheme=jubjub, public_key={}",
                made.id, made.public_key
            )
        );
        assert!(log[1]
            .1
            .starts_with(&format!("credential_id={}, name=copy,", copy.id)));
        assert_eq!(log[2].1, format!("credential_id={}, name=copy", copy.id));
    }

    const CHAIN_SPECIFIC: [&str; 3] = ["midnight", "jubjub", "passport"];

    /// `source` without its `#[cfg(test)]` modules, each cut from its attribute to the closing
    /// brace rustfmt puts at the module's own indentation.
    fn without_test_modules(source: &str) -> String {
        let mut kept = Vec::new();
        let mut lines = source.lines().peekable();
        while let Some(line) = lines.next() {
            let module = lines.peek().map(|next| next.trim_start());
            if line.trim() == "#[cfg(test)]" && module.is_some_and(|m| m.starts_with("mod ")) {
                let header = lines.next().unwrap();
                if header.trim_end().ends_with('{') {
                    let indent = &line[..line.len() - line.trim_start().len()];
                    let close = format!("{indent}}}");
                    lines.by_ref().find(|l| *l == close);
                }
                continue;
            }
            kept.push(line);
        }
        kept.join("\n")
    }

    /// The top-level items of `source` named after a credential, with their doc comments and
    /// attributes, each up to its closing brace at the start of a line.
    fn credential_items(source: &str) -> Vec<String> {
        let lines: Vec<&str> = source.lines().collect();
        let mut items = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let header = line
                .trim_start_matches("pub(crate) ")
                .trim_start_matches("pub ");
            let Some(rest) = ["fn ", "struct ", "enum "]
                .iter()
                .find_map(|keyword| header.strip_prefix(keyword))
            else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.to_lowercase().contains("credential") {
                continue;
            }
            let mut start = i;
            while start > 0
                && (lines[start - 1].starts_with("///") || lines[start - 1].starts_with("#["))
            {
                start -= 1;
            }
            let end = if line.trim_end().ends_with(';') {
                i
            } else {
                (i..lines.len())
                    .find(|&j| lines[j] == "}")
                    .unwrap_or(lines.len() - 1)
            };
            items.push(lines[start..=end].join("\n"));
        }
        items
    }

    #[test]
    fn generic_credential_code_names_no_chain() {
        let whole_files = [
            (
                "ows-core/src/credential_file.rs",
                include_str!("../../ows-core/src/credential_file.rs"),
            ),
            (
                "ows-core/src/api_key.rs",
                include_str!("../../ows-core/src/api_key.rs"),
            ),
            (
                "ows-core/src/policy.rs",
                include_str!("../../ows-core/src/policy.rs"),
            ),
            (
                "ows-lib/src/record_store.rs",
                include_str!("record_store.rs"),
            ),
            (
                "ows-lib/src/credential_store.rs",
                include_str!("credential_store.rs"),
            ),
            (
                "ows-lib/src/credential_ops.rs",
                include_str!("credential_ops.rs"),
            ),
            (
                "ows-lib/src/credential_audit.rs",
                include_str!("credential_audit.rs"),
            ),
            ("ows-lib/src/error.rs", include_str!("error.rs")),
            (
                "ows-lib/src/policy_engine.rs",
                include_str!("policy_engine.rs"),
            ),
            (
                "ows-signer/src/credential.rs",
                include_str!("../../ows-signer/src/credential.rs"),
            ),
            (
                "ows-cli/src/commands/credential.rs",
                include_str!("../../ows-cli/src/commands/credential.rs"),
            ),
            (
                "ows-cli/src/commands/key.rs",
                include_str!("../../ows-cli/src/commands/key.rs"),
            ),
        ];
        // Files that also hold wallet code, which may name a chain, are scanned only in their
        // credential items.
        let shared_files = [
            ("ows-lib/src/types.rs", include_str!("types.rs")),
            ("ows-lib/src/key_ops.rs", include_str!("key_ops.rs")),
            (
                "ows-cli/src/main.rs",
                include_str!("../../ows-cli/src/main.rs"),
            ),
            (
                "bindings/node/src/lib.rs",
                include_str!("../../../../bindings/node/src/lib.rs"),
            ),
            (
                "bindings/python/src/lib.rs",
                include_str!("../../../../bindings/python/src/lib.rs"),
            ),
        ];

        let mut generic: Vec<(&str, String)> = whole_files
            .iter()
            .map(|(file, source)| (*file, without_test_modules(source)))
            .collect();
        for (file, source) in shared_files {
            let items = credential_items(&without_test_modules(source));
            assert!(!items.is_empty(), "{file} has no credential items");
            generic.extend(items.into_iter().map(|item| (file, item)));
        }
        for (file, code) in generic {
            let code = code.to_lowercase();
            for name in CHAIN_SPECIFIC {
                assert!(
                    !code.contains(name),
                    "{file} names `{name}` outside its tests"
                );
            }
        }
    }

    #[test]
    fn the_scan_cuts_only_test_modules() {
        let source = "fn a() {}\n#[cfg(test)]\nfn helper() {}\n#[cfg(test)]\nmod tests {\n    fn b() {}\n}\nfn c() {}\n#[cfg(test)]\nmod more;\nfn d() {}";
        assert_eq!(
            without_test_modules(source),
            "fn a() {}\n#[cfg(test)]\nfn helper() {}\nfn c() {}\nfn d() {}"
        );
        let items = credential_items(
            "/// Doc.\npub fn make_credential() {\n    body();\n}\nfn other() {}\npub struct CredentialId(String);",
        );
        assert_eq!(
            items,
            [
                "/// Doc.\npub fn make_credential() {\n    body();\n}",
                "pub struct CredentialId(String);"
            ]
        );
    }
}
