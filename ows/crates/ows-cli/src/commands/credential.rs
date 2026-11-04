use crate::CliError;

fn print_info(info: &ows_lib::CredentialInfo) {
    println!("Credential: {}", info.id);
    println!("Name:       {}", info.name);
    println!("Chain:      {}", info.chain);
    println!("Scheme:     {}", info.scheme);
    println!("Origin:     {}", info.origin.as_str());
    println!("Public key: {}", info.public_key);
}

fn scheme_of(info: &ows_lib::CredentialInfo) -> Option<Box<dyn ows_signer::CredentialScheme>> {
    ows_signer::credential_scheme(info.chain, Some(&info.scheme)).ok()
}

fn print_next_step(info: &ows_lib::CredentialInfo) {
    if let Some(hint) = scheme_of(info).and_then(|scheme| scheme.create_hint()) {
        eprintln!();
        eprintln!("Next: {hint}");
    }
}

pub fn create(name: &str, chain: &str, scheme: Option<&str>) -> Result<(), CliError> {
    let passphrase = super::read_passphrase();
    let info = ows_lib::create_credential(name, chain, scheme, Some(passphrase.as_str()), None)?;

    print_info(&info);
    print_next_step(&info);
    Ok(())
}

pub fn import(name: &str, chain: &str, scheme: Option<&str>) -> Result<(), CliError> {
    let secret = super::read_private_key()?;
    let passphrase = super::read_passphrase();
    let info = ows_lib::import_credential(
        name,
        chain,
        scheme,
        &secret,
        Some(passphrase.as_str()),
        None,
    )?;

    print_info(&info);
    print_next_step(&info);
    eprintln!();
    eprintln!(
        "WARNING: an imported key may also live elsewhere (another wallet, a device, a backup)."
    );
    eprintln!(
        "OWS cannot stop another signer from using it, and its policies bind only this vault."
    );
    Ok(())
}

pub fn list() -> Result<(), CliError> {
    let credentials = ows_lib::list_credentials(None)?;

    if credentials.is_empty() {
        println!("No credentials found.");
        return Ok(());
    }

    for c in &credentials {
        println!("ID:         {}", c.id);
        println!("Name:       {}", c.name);
        println!("Chain:      {}", c.chain);
        println!("Scheme:     {}", c.scheme);
        println!("Origin:     {}", c.origin.as_str());
        println!("Public key: {}", c.public_key);
        println!("Created:    {}", c.created_at);
        println!();
    }

    Ok(())
}

pub fn delete(credential: &str, confirm: bool) -> Result<(), CliError> {
    let info = ows_lib::get_credential(credential, None)?;
    if let Some(warning) = scheme_of(&info).and_then(|scheme| scheme.delete_warning()) {
        eprintln!("WARNING: {warning}");
    }

    if !confirm {
        eprintln!("To delete a credential, pass --confirm.");
        eprintln!(
            "A deleted credential's key cannot be recovered, and agent keys lose access to it."
        );
        return Err(CliError::InvalidArgs(
            "--confirm is required to delete a credential".into(),
        ));
    }

    ows_lib::delete_credential(&info.id, None)?;

    println!("Credential deleted: {} ({})", info.id, info.name);
    Ok(())
}

/// `OWS_PASSPHRASE`, or a prompt, holds the owner's passphrase or an agent token; ows-lib tells the
/// two apart and records which one signed.
pub fn sign(
    credential: &str,
    chain: &str,
    request: &str,
    json_output: bool,
) -> Result<(), CliError> {
    let passphrase = super::read_passphrase();
    let signature =
        ows_lib::sign_with_credential(credential, chain, request, Some(passphrase.as_str()), None)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&signature.to_json())?);
    } else {
        println!("{}", signature.signature);
    }
    Ok(())
}
