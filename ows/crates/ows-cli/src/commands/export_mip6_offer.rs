use crate::CliError;
use ows_core::ChainType;

/// Export a maker sealed/proven Midnight swap transaction as MIP-0006 JSON with a `zswapoffer…` field.
pub fn run(chain_str: &str, tx_hex: &str, json_output: bool) -> Result<(), CliError> {
    let chain = crate::parse_chain(chain_str)?;
    if chain.chain_type != ChainType::Midnight {
        return Err(CliError::InvalidArgs(
            "export-mip6-offer is only supported for Midnight chains".into(),
        ));
    }
    let hex_s = tx_hex.trim().strip_prefix("0x").unwrap_or(tx_hex.trim());
    let bytes = hex::decode(hex_s)
        .map_err(|e| CliError::InvalidArgs(format!("invalid maker transaction hex: {e}")))?;
    let offer = ows_lib::chains::midnight::export_mip6_offer_json_from_maker_bytes(&bytes)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&offer)?);
    } else {
        println!("{}", serde_json::to_string(&offer)?);
    }
    Ok(())
}
