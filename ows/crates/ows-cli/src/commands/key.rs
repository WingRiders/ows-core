use crate::{audit, CliError};

/// Create a new API key for agent access to wallets.
pub fn create(
    name: &str,
    wallet_names: &[String],
    credential_names: &[String],
    policy_ids: &[String],
    expires_at: Option<&str>,
) -> Result<(), CliError> {
    if wallet_names.is_empty() && credential_names.is_empty() {
        return Err(CliError::InvalidArgs(
            "at least one --wallet or --credential is required".into(),
        ));
    }

    // Resolve wallet names to IDs
    let mut wallet_ids = Vec::with_capacity(wallet_names.len());
    for name_or_id in wallet_names {
        let info = ows_lib::get_wallet(name_or_id, None)?;
        wallet_ids.push(info.id);
    }

    let mut credential_ids = Vec::with_capacity(credential_names.len());
    for name_or_id in credential_names {
        let info = ows_lib::get_credential(name_or_id, None)?;
        credential_ids.push(info.id);
    }

    // Read passphrase (needed to decrypt wallet mnemonics for re-encryption)
    let passphrase = super::read_passphrase();

    let (token, key_file) = ows_lib::key_ops::create_api_key_with_credentials(
        name,
        &wallet_ids,
        &credential_ids,
        policy_ids,
        &passphrase,
        expires_at,
        None,
    )?;

    audit::log_api_key_created(&key_file.id, name, &wallet_ids, policy_ids);

    println!("API key created: {}", key_file.id);
    println!("Name:            {name}");
    if !wallet_ids.is_empty() {
        println!("Wallets:         {}", wallet_ids.join(", "));
    }
    if !credential_ids.is_empty() {
        println!("Credentials:     {}", credential_ids.join(", "));
    }
    if !policy_ids.is_empty() {
        println!("Policies:        {}", policy_ids.join(", "));
    }
    if let Some(exp) = &key_file.expires_at {
        println!("Expires:         {exp}");
    }
    println!();
    eprintln!("TOKEN (shown once — save it now):");
    println!("{token}");

    Ok(())
}

/// List all API keys (tokens are never shown).
pub fn list() -> Result<(), CliError> {
    let keys = ows_lib::key_store::list_api_keys(None)?;

    if keys.is_empty() {
        println!("No API keys found.");
        return Ok(());
    }

    for k in &keys {
        // Labels only widen for a key that holds credentials, so a wallet-only key prints as before.
        let w = if k.credential_ids.is_empty() { 10 } else { 13 };
        println!("{:<w$}{}", "ID:", k.id);
        println!("{:<w$}{}", "Name:", k.name);
        if !k.wallet_ids.is_empty() || k.credential_ids.is_empty() {
            println!("{:<w$}{}", "Wallets:", k.wallet_ids.join(", "));
        }
        if !k.credential_ids.is_empty() {
            println!("{:<w$}{}", "Credentials:", k.credential_ids.join(", "));
        }
        println!("{:<w$}{}", "Policies:", k.policy_ids.join(", "));
        if let Some(ref exp) = k.expires_at {
            println!("{:<w$}{exp}", "Expires:");
        }
        println!("{:<w$}{}", "Created:", k.created_at);
        println!();
    }

    Ok(())
}

/// Revoke (delete) an API key.
pub fn revoke(id: &str, confirm: bool) -> Result<(), CliError> {
    if !confirm {
        eprintln!("To revoke an API key, pass --confirm.");
        return Err(CliError::InvalidArgs(
            "--confirm is required to revoke an API key".into(),
        ));
    }

    let key = ows_lib::key_ops::revoke_api_key(id, None)?;

    audit::log_api_key_revoked(&key.id, &key.name, &key.wallet_ids);

    println!("API key revoked: {} ({})", key.id, key.name);
    Ok(())
}
