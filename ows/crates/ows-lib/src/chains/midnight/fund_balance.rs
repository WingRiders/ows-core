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
    block_on, chain_needs_dust_fee_registration, format_dust_specks, fund_balance_skip_dust_sync,
    get_dust_balance_for_display_scoped, get_shielded_balances_for_display_scoped,
    get_unshielded_utxos_for_display_scoped, midnight_sync_log_enabled, parse_token_type,
    SyncCacheScope, UnshieldedUtxo,
};
use crate::error::OwsLibError;

fn print_addresses(
    chain_id: &str,
    unshielded_address: &str,
    shielded_seed: Option<&SecretBytes>,
    dust_seed: Option<&SecretBytes>,
) -> Result<(), OwsLibError> {
    eprintln!("Addresses:");
    eprintln!("  Unshielded: {unshielded_address}");

    if let Some(seed) = shielded_seed {
        let shielded_addr = MidnightSigner
            .derive_shielded_address_from_seed_for_chain_id(chain_id, seed.expose())
            .map_err(|e| OwsLibError::InvalidInput(e.to_string()))?;
        eprintln!("  Shielded:   {shielded_addr}");
    } else {
        eprintln!("  Shielded:   (unavailable: missing shielded seed)");
    }

    if let Some(seed) = dust_seed {
        let seed_arr: [u8; 32] = seed.expose().try_into().map_err(|_| {
            OwsLibError::InvalidInput("dust seed must be 32 bytes (wallet corruption?)".into())
        })?;
        let dust_addr = MidnightSigner
            .derive_dust_address_from_seed(&seed_arr)
            .map_err(|e| OwsLibError::InvalidInput(e.to_string()))?;
        eprintln!("  Dust:       {dust_addr}");
    } else {
        eprintln!("  Dust:       (unavailable: missing dust seed)");
    }
    eprintln!();
    Ok(())
}

fn print_dust_status(
    indexer_url: &str,
    unshielded_utxos: &[UnshieldedUtxo],
    dust_seed: Option<&SecretBytes>,
    sync_scope: &SyncCacheScope,
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

    if let Some(seed) = dust_seed {
        eprintln!("  DUST seed: available");
        if fund_balance_skip_dust_sync() {
            eprintln!(
                "  DUST balance: skipped (OWS_MIDNIGHT_SKIP_DUST_BALANCE=1; fee-mode lines above still apply)"
            );
            eprintln!();
            return Ok(());
        }
        if midnight_sync_log_enabled() {
            eprintln!(
                "  Syncing DUST ledger (resumes ~/.ows/sync/midnight/dust cache, then catches up; progress below)..."
            );
        }
        let seed_arr: [u8; 32] = match seed.expose().try_into() {
            Ok(s) => s,
            Err(_) => {
                eprintln!("  DUST: unavailable (dust seed must be 32 bytes)");
                return Ok(());
            }
        };

        let chain_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        match block_on(get_dust_balance_for_display_scoped(
            indexer_url,
            &seed_arr,
            chain_time,
            sync_scope,
        )) {
            Ok((dust_utxo_count, dust_sum)) => {
                eprintln!("  DUST UTXOs: {dust_utxo_count}");
                let dust = format_dust_specks(dust_sum);
                eprintln!("  DUST balance: {dust} (best-effort, wall-clock time)");
            }
            Err(e) => {
                eprintln!("  DUST: unavailable ({e})");
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
    let sync_scope = sync_scope_for_wallet(wallet_name, Some(chain_id), vault_path);

    if midnight_sync_log_enabled() {
        eprintln!("[ows-midnight] syncing unshielded balance from indexer…");
    }
    let unshielded_utxos = block_on(get_unshielded_utxos_for_display_scoped(
        &indexer_url,
        &address,
        &sync_scope,
    ))
    .map_err(|e| OwsLibError::InvalidInput(e.to_string()))?;
    let mut unshielded: BTreeMap<String, u128> = BTreeMap::new();
    for u in &unshielded_utxos {
        *unshielded.entry(u.token_type.clone()).or_insert(0) += u.value;
    }

    let (shielded_seed, dust_seed) = decrypt_auxiliary_seeds_with_fallback(
        wallet_name,
        Some(0),
        vault_path,
        &mut prompt_passphrase,
    )?;

    let shielded = if let Some(seed) = shielded_seed.as_ref() {
        if midnight_sync_log_enabled() {
            eprintln!(
                "[ows-midnight] syncing shielded balance from indexer (may take a while on first run)…"
            );
        }
        block_on(get_shielded_balances_for_display_scoped(
            &indexer_url,
            seed.expose(),
            &sync_scope,
        ))
        .map_err(|e| OwsLibError::InvalidInput(e.to_string()))?
    } else {
        Default::default()
    };

    print_addresses(
        chain_id,
        &address,
        shielded_seed.as_ref(),
        dust_seed.as_ref(),
    )?;

    if unshielded.is_empty() && shielded.is_empty() {
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
        eprintln!("Shielded balances:");
        if shielded.is_empty() {
            eprintln!("  (none — no unspent shielded coins found after full sync)");
        } else {
            for (token_type, amount) in shielded {
                println!("{:>24} {}", amount, token_type);
            }
        }
        eprintln!();
    }

    if chain_needs_dust_fee_registration(chain_id) {
        print_dust_status(
            &indexer_url,
            &unshielded_utxos,
            dust_seed.as_ref(),
            &sync_scope,
        )?;
    }

    Ok(())
}
