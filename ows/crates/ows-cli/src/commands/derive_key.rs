use ows_signer::{Curve, HdDeriver, Mnemonic};

use crate::CliError;

pub fn run(mnemonic: &str, passphrase: &str, path: &str, curve: Curve) -> Result<(), CliError> {
    let mnemonic = Mnemonic::from_phrase(mnemonic)?;
    let key = HdDeriver::derive_from_mnemonic(&mnemonic, passphrase, path, curve)?;
    println!("{}", hex::encode(key.expose()));
    Ok(())
}
