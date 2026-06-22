//! `ows fund balance --chain midnight:*` — delegates to `ows-lib`.

use crate::CliError;
use ows_core::Chain;
use ows_lib::types::AccountInfo;

pub(super) fn balance(
    wallet_name: &str,
    accounts: &[AccountInfo],
    chain: &Chain,
) -> Result<(), CliError> {
    let account = super::find_account_for_chain(accounts, chain)?;
    ows_lib::chains::midnight::print_fund_balance(
        wallet_name,
        &account.address,
        chain,
        Some(super::super::vault_dir().as_path()),
        || crate::commands::read_passphrase().to_string(),
    )
    .map_err(|e| match e {
        ows_lib::OwsLibError::InvalidInput(msg) => CliError::InvalidArgs(msg),
        ows_lib::OwsLibError::BroadcastFailed(msg) => CliError::InvalidArgs(msg),
        other => other.into(),
    })
}
