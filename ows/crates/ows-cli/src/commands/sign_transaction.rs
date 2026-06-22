use crate::CliError;

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    // Check for API token in passphrase — route through library for policy enforcement
    let passphrase = super::peek_passphrase();
    if passphrase
        .as_deref()
        .is_some_and(|p| p.starts_with(ows_lib::key_store::TOKEN_PREFIX))
    {
        let result = ows_lib::sign_transaction(
            wallet_name,
            chain_str,
            tx_hex,
            passphrase.as_deref(),
            Some(index),
            None,
        )?;
        return print_result(&result, json_output);
    }

    let ctx = super::resolve_owner_sign_context(wallet_name, chain_str, tx_hex, index, false)?;
    let result = super::sign_owner_transaction(&ctx)?;
    print_result(&result, json_output)
}

fn print_result(result: &ows_lib::SignResult, json_output: bool) -> Result<(), CliError> {
    if json_output {
        let obj = serde_json::json!({
            "signature": result.signature,
            "recovery_id": result.recovery_id,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
        return Ok(());
    }

    println!("{}", result.signature);
    Ok(())
}
