use crate::CliError;
use ows_core::Chain;
use ows_lib::types::AccountInfo;

mod midnight;

/// Returns the wallet account for a funding chain.
///
/// Tries an exact CAIP-2 match first, then falls back to any account in the same
/// chain family (e.g. `eip155:8453` → stored `eip155:1`), since universal wallets
/// keep one row per family using [`ows_core::default_chain_for_type`].
pub(super) fn find_account_for_chain<'a>(
    accounts: &'a [AccountInfo],
    chain: &Chain,
) -> Result<&'a AccountInfo, CliError> {
    let chain_id = chain.chain_id;
    if let Some(acct) = accounts.iter().find(|a| a.chain_id == chain_id) {
        return Ok(acct);
    }

    let prefix = format!("{}:", chain.chain_type.namespace());
    if let Some(acct) = accounts
        .iter()
        .find(|a| a.chain_id.starts_with(prefix.as_str()))
    {
        return Ok(acct);
    }

    Err(CliError::InvalidArgs(format!(
        "wallet has no account for chain \"{chain_id}\""
    )))
}

/// `ows fund buy --wallet <name> [--chain base] [--token USDC]`
///
/// Creates a MoonPay deposit that generates multi-chain deposit addresses.
/// Anyone can send crypto from any chain — it auto-converts to the target token.
pub fn run(wallet_name: &str, chain: Option<&str>, token: Option<&str>) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None)?;
    let chain_name = chain.unwrap_or("base");
    let chain = crate::parse_chain(chain_name)?;

    let account = find_account_for_chain(&wallet.accounts, &chain)?;
    let address = &account.address;
    let token_name = token.unwrap_or("USDC");

    eprintln!("Creating deposit for wallet \"{wallet_name}\" ({address})");
    eprintln!("Target: {token_name} on {chain_name}");

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let result = rt.block_on(ows_pay::fund::fund(
        address,
        Some(chain_name),
        Some(token_name),
    ))?;

    eprintln!();
    eprintln!("Deposit created (ID: {})", result.deposit_id);
    eprintln!();

    // Show deposit addresses.
    if !result.wallets.is_empty() {
        eprintln!("Send crypto to any of these addresses:");
        for (chain, addr) in &result.wallets {
            eprintln!("  {chain:>10}  {addr}");
        }
        eprintln!();
    }

    eprintln!("{}", result.instructions);
    eprintln!();

    // Print the deposit URL (opens in browser for a web flow).
    println!("{}", result.deposit_url);

    // Try to open in browser.
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(&result.deposit_url)
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(&result.deposit_url)
            .spawn();
    }

    Ok(())
}

/// `ows fund balance --wallet <name> [--chain base]`
///
/// Check token balances. Midnight chains use the Midnight indexer (see `midnight`
/// submodule); everything else goes through MoonPay's aggregated balance API.
pub fn balance(wallet_name: &str, chain: Option<&str>) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None)?;
    let chain_name = chain.unwrap_or("base");
    let chain = crate::parse_chain(chain_name)?;

    if chain.chain_type == ows_core::ChainType::Midnight {
        return midnight::balance(wallet_name, &wallet.accounts, &chain);
    }

    let account = find_account_for_chain(&wallet.accounts, &chain)?;
    let address = account.address.clone();

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let balances = rt.block_on(ows_pay::fund::get_balances(&address, Some(chain_name)))?;

    if balances.is_empty() {
        eprintln!("No tokens found for {address} on {chain_name}");
        return Ok(());
    }

    for token in &balances {
        let amount = token.balance.amount;
        let value = token.balance.value;
        println!(
            "{:>12.6} {:6} ${:<10.2}  {}",
            amount, token.symbol, value, token.name
        );
    }

    Ok(())
}
