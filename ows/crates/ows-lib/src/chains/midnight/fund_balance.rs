//! `ows fund balance --chain midnight:*` display (indexer-backed balances).

use std::collections::BTreeMap;
use std::path::Path;

use ows_core::Chain;
use ows_signer::chains::MidnightSigner;
use ows_signer::SecretBytes;

use super::wallet::{
    decrypt_auxiliary_seeds_with_fallback, resolve_indexer_url, sync_scope_for_wallet,
};
use super::{
    block_on, format_dust_specks, fund_balance_skip_dust_sync, get_dust_balance_for_display_scoped,
    get_shielded_balances_for_display_scoped, get_unshielded_utxos_for_display_scoped,
    midnight_sync_log_enabled, parse_token_type, shielded_sync::ShieldedDisplayBalances,
    UnshieldedUtxo,
};
use crate::error::OwsLibError;

struct MidnightWalletAddresses {
    unshielded: String,
    shielded: Option<String>,
    dust: Option<String>,
}

fn derive_midnight_wallet_addresses(
    chain_id: &str,
    unshielded_address: &str,
    shielded_seed: Option<&SecretBytes>,
    dust_seed: Option<&SecretBytes>,
) -> Result<MidnightWalletAddresses, OwsLibError> {
    let mut out = MidnightWalletAddresses {
        unshielded: unshielded_address.to_string(),
        shielded: None,
        dust: None,
    };

    if let Some(seed) = shielded_seed {
        out.shielded = Some(
            MidnightSigner
                .derive_shielded_address_from_seed_for_chain_id(chain_id, seed.expose())
                .map_err(|e| OwsLibError::InvalidInput(e.to_string()))?,
        );
    }

    if let Some(seed) = dust_seed {
        let seed_arr: [u8; 32] = seed.expose().try_into().map_err(|_| {
            OwsLibError::InvalidInput("dust seed must be 32 bytes (wallet corruption?)".into())
        })?;
        out.dust = Some(
            MidnightSigner
                .derive_dust_address_from_seed_for_chain_id(chain_id, &seed_arr)
                .map_err(|e| OwsLibError::InvalidInput(e.to_string()))?,
        );
    }

    Ok(out)
}

fn print_addresses(addrs: &MidnightWalletAddresses) -> Result<(), OwsLibError> {
    eprintln!("Addresses:");
    eprintln!("  Unshielded: {}", addrs.unshielded);
    match &addrs.shielded {
        Some(a) => eprintln!("  Shielded:   {a}"),
        None => eprintln!("  Shielded:   (unavailable: missing shielded seed)"),
    }
    match &addrs.dust {
        Some(a) => eprintln!("  Dust:       {a}"),
        None => eprintln!("  Dust:       (unavailable: missing dust seed)"),
    }
    eprintln!();
    Ok(())
}

type DustBalanceResult = Result<(usize, u128), super::PayError>;

fn print_dust_status(
    unshielded_utxos: &[UnshieldedUtxo],
    dust_seed: Option<&SecretBytes>,
    dust_balance: Option<DustBalanceResult>,
) -> Result<(), OwsLibError> {
    eprintln!("Dust status (fees):");

    let night_wire = parse_token_type(Some("night"))
        .map_err(|e| OwsLibError::InvalidInput(e.to_string()))?
        .to_wire_token_type();
    let total_night = unshielded_utxos
        .iter()
        .filter(|u| u.token_type.eq_ignore_ascii_case(&night_wire))
        .count();
    let registered_night = unshielded_utxos
        .iter()
        .filter(|u| u.token_type.eq_ignore_ascii_case(&night_wire))
        .filter(|u| u.registered_for_dust_generation)
        .count();
    let unregistered_night = total_night.saturating_sub(registered_night);

    if total_night == 0 {
        eprintln!("  NIGHT UTXOs: none found (dust generation uses NIGHT inputs)");
    } else {
        eprintln!(
            "  NIGHT UTXOs: total={total_night} registered={registered_night} unregistered={unregistered_night}"
        );
        if unregistered_night > 0 {
            eprintln!(
                "  Fee mode: generationless DUST (can be derived from unregistered NIGHT inputs)"
            );
        } else {
            eprintln!("  Fee mode: DUST spend proofs (all NIGHT inputs already registered)");
        }
    }

    if dust_seed.is_some() {
        eprintln!("  DUST seed: available");
        if fund_balance_skip_dust_sync() {
            eprintln!(
                "  DUST balance: skipped (OWS_MIDNIGHT_SKIP_DUST_BALANCE=1; fee-mode lines above still apply)"
            );
            eprintln!();
            return Ok(());
        }
        match dust_balance {
            Some(Ok((dust_utxo_count, dust_sum))) => {
                eprintln!("  DUST UTXOs: {dust_utxo_count}");
                let dust = format_dust_specks(dust_sum);
                eprintln!("  DUST balance (specks): {dust_sum}");
                eprintln!("  DUST balance: {dust} (best-effort, wall-clock time)");
            }
            Some(Err(e)) => {
                eprintln!("  DUST: unavailable ({e})");
            }
            None => {
                eprintln!("  DUST: unavailable (dust seed must be 32 bytes)");
            }
        }
    } else {
        eprintln!("  DUST seed: unavailable (can't sync dust ledger state)");
    }
    eprintln!();
    Ok(())
}

/// Indexer-backed balance display for `ows fund balance --chain midnight:*`.
pub fn print_fund_balance(
    wallet_name: &str,
    stored_unshielded_address: &str,
    chain: &Chain,
    vault_path: Option<&Path>,
    mut prompt_passphrase: impl FnMut() -> String,
) -> Result<(), OwsLibError> {
    let chain_id = chain.chain_id;
    let address = MidnightSigner::reencode_unshielded_address_for_chain_id(
        chain_id,
        stored_unshielded_address,
    )
    .map_err(|e| OwsLibError::InvalidInput(e.to_string()))?;

    let indexer_url = resolve_indexer_url(chain_id)?;
    let mut sync_scope = sync_scope_for_wallet(wallet_name, Some(chain_id), vault_path);
    super::tip_verify::refresh_indexer_block_height(&mut sync_scope, &indexer_url);

    let (shielded_seed, dust_seed) = decrypt_auxiliary_seeds_with_fallback(
        wallet_name,
        Some(0),
        vault_path,
        &mut prompt_passphrase,
    )?;

    print_addresses(&derive_midnight_wallet_addresses(
        chain_id,
        &address,
        shielded_seed.as_ref(),
        dust_seed.as_ref(),
    )?)?;

    if midnight_sync_log_enabled() {
        eprintln!("[ows-midnight] syncing unshielded, shielded, and dust balances in parallel…");
    }

    let dust_seed_arr: Option<[u8; 32]> =
        dust_seed.as_ref().and_then(|s| s.expose().try_into().ok());
    let chain_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let skip_dust = fund_balance_skip_dust_sync() || dust_seed_arr.is_none();

    let (unshielded_utxos, shielded_report, dust_balance) = block_on(async {
        let indexer_url = indexer_url.clone();
        let address = address.clone();
        let sync_scope = sync_scope.clone();

        let unshielded_fut =
            get_unshielded_utxos_for_display_scoped(&indexer_url, &address, &sync_scope);

        let shielded_fut = async {
            if let Some(seed) = shielded_seed.as_ref() {
                get_shielded_balances_for_display_scoped(&indexer_url, seed.expose(), &sync_scope)
                    .await
            } else {
                Ok(ShieldedDisplayBalances::default())
            }
        };

        let dust_fut = async {
            if skip_dust {
                return None;
            }
            let seed_arr = dust_seed_arr.expect("checked above");
            Some(
                get_dust_balance_for_display_scoped(
                    &indexer_url,
                    &seed_arr,
                    chain_time,
                    &sync_scope,
                )
                .await,
            )
        };

        let (unshielded_res, shielded_res, dust_res) =
            tokio::join!(unshielded_fut, shielded_fut, dust_fut);
        Ok::<_, OwsLibError>((
            unshielded_res.map_err(|e| OwsLibError::InvalidInput(e.to_string()))?,
            shielded_res.map_err(|e| OwsLibError::InvalidInput(e.to_string()))?,
            dust_res,
        ))
    })?;

    let mut unshielded: BTreeMap<String, u128> = BTreeMap::new();
    for u in &unshielded_utxos {
        *unshielded.entry(u.token_type.clone()).or_insert(0) += u.value;
    }
    let shielded = shielded_report.spendable;
    let shielded_session_only = shielded_report.session_only;

    if unshielded.is_empty() && shielded.is_empty() && shielded_session_only.is_empty() {
        eprintln!("No Midnight tokens found for {address} on {chain_id}");
        return Ok(());
    }

    if !unshielded.is_empty() {
        eprintln!("Unshielded balances:");
        for (token_type, amount) in unshielded {
            println!("{:>24} {}", amount, token_type);
        }
        eprintln!();
    }
    if shielded_seed.is_some() {
        eprintln!("Shielded balances (zswapLedgerEvents):");
        if shielded.is_empty() {
            eprintln!("  (none — no unspent shielded coins after zswap ledger sync)");
        } else {
            for (token_type, amount) in &shielded {
                println!("{:>24} {}", amount, token_type);
            }
        }
        if !shielded_session_only.is_empty() {
            eprintln!();
            eprintln!(
                "Shielded viewing-key session only (OWS_MIDNIGHT_SHIELDED_SESSION_SYNC=1 diagnostic — not in zswap replay):"
            );
            for (token_type, amount) in &shielded_session_only {
                println!("{:>24} {}", amount, token_type);
            }
        }
        eprintln!();
    }

    print_dust_status(&unshielded_utxos, dust_seed.as_ref(), dust_balance)?;

    Ok(())
}
