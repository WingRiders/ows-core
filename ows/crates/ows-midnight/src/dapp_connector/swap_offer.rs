//! MIP-0005 offer files, as `balanceSealedTransaction` maker inputs.
//!
//! An offer file is a proven, deliberately imbalanced Midnight `Transaction` shared as a bech32m string
//! under the `swapoffer` HRP. Decoded, it is the sealed maker offer the merge path completes.

use bech32::Bech32m;
use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_ledger::structure::{ProofMarker, Transaction};
use midnight_serialize::{tagged_serialize, Deserializable as _};
use midnight_storage::db::InMemoryDB;
use transient_crypto::commitment::PureGeneratorPedersen;

use super::build::err;

type TxSealed = Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB>;

/// MIP-0005 human-readable part (`swapoffer1…` on the wire).
pub const SWAP_OFFER_HRP: &str = "swapoffer";

/// Whether `s` is a MIP-0005 offer string. bech32 also allows an all-uppercase string, so the HRP is
/// matched case-insensitively.
pub(super) fn is_swap_offer(s: &str) -> bool {
    s.get(..SWAP_OFFER_HRP.len() + 1)
        .is_some_and(|p| p.eq_ignore_ascii_case(&format!("{SWAP_OFFER_HRP}1")))
}

/// Decode a MIP-0005 `swapoffer1…` string into tagged transaction bytes, the form every other maker
/// input takes.
///
/// The checksum is verified by driving the Bech32m engine directly: the crate's checked decoder caps a
/// string at 90 characters, which MIP-0005 forbids, and a proven offer runs to thousands. MIP-0005
/// carries the ledger's serialization as-is; a payload written without the ledger's tag is accepted
/// too and re-tagged.
pub(super) fn decode_swap_offer(s: &str) -> Result<Vec<u8>, std::io::Error> {
    use bech32::primitives::checksum;
    use bech32::primitives::decode::UncheckedHrpstring;
    use bech32::{Checksum, Fe32};

    let unchecked = UncheckedHrpstring::new(s.trim())
        .map_err(|e| err(format!("invalid swapoffer bech32: {e}")))?;
    if !unchecked
        .hrp()
        .as_str()
        .eq_ignore_ascii_case(SWAP_OFFER_HRP)
    {
        return Err(err(format!(
            "expected the swapoffer bech32 HRP, got {}",
            unchecked.hrp().as_str()
        )));
    }
    if unchecked.data_part_ascii().len() < Bech32m::CHECKSUM_LENGTH {
        return Err(err("invalid swapoffer bech32: data too short for checksum"));
    }
    let mut eng = checksum::Engine::<Bech32m>::new();
    eng.input_hrp(unchecked.hrp());
    for &b in unchecked.data_part_ascii() {
        eng.input_fe(Fe32::from_char_unchecked(b));
    }
    if eng.residue() != &Bech32m::TARGET_RESIDUE {
        return Err(err("invalid swapoffer bech32 checksum"));
    }
    let bytes: Vec<u8> = unchecked.remove_checksum::<Bech32m>().byte_iter().collect();
    if bytes.starts_with(b"midnight:") {
        return Ok(bytes);
    }
    let tx = TxSealed::deserialize(&mut bytes.as_slice(), 0).map_err(|e| {
        err(format!(
            "swapoffer payload is not a sealed transaction: {e}"
        ))
    })?;
    let mut tagged = Vec::new();
    tagged_serialize(&tx, &mut tagged).map_err(|e| err(format!("serialize tx: {e}")))?;
    Ok(tagged)
}

/// Encode transaction bytes as a MIP-0005 `swapoffer1…` string, without the 90-character cap.
#[cfg(test)]
pub(super) fn encode_swap_offer(bytes: &[u8]) -> String {
    use bech32::{ByteIterExt as _, Fe32IterExt as _, Hrp};
    let hrp = Hrp::parse(SWAP_OFFER_HRP).expect("valid HRP");
    bytes
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .chars()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_serialize::{tagged_deserialize, Serializable as _};

    fn sealed_maker() -> Vec<u8> {
        let hex_str = include_str!("testdata/sealed_maker_preprod.hex").trim();
        hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap()
    }

    #[test]
    fn round_trips_a_sealed_maker() {
        let bytes = sealed_maker();
        let offer = encode_swap_offer(&bytes);
        assert!(offer.starts_with("swapoffer1"));
        assert!(
            offer.len() > 90,
            "a real offer exceeds bech32's 90-character cap"
        );
        assert!(is_swap_offer(&offer));
        assert_eq!(decode_swap_offer(&offer).unwrap(), bytes);
    }

    #[test]
    fn accepts_an_all_uppercase_offer() {
        let bytes = sealed_maker();
        let upper = encode_swap_offer(&bytes).to_ascii_uppercase();
        assert!(is_swap_offer(&upper));
        assert_eq!(decode_swap_offer(&upper).unwrap(), bytes);
    }

    #[test]
    fn retags_an_untagged_payload() {
        let tagged = sealed_maker();
        let tx: TxSealed = tagged_deserialize(&mut tagged.as_slice()).unwrap();
        let mut untagged = Vec::new();
        tx.serialize(&mut untagged).unwrap();
        assert!(!untagged.starts_with(b"midnight:"));
        assert_eq!(
            decode_swap_offer(&encode_swap_offer(&untagged)).unwrap(),
            tagged
        );
    }

    #[test]
    fn rejects_a_wrong_hrp_or_a_bad_checksum() {
        use bech32::{ByteIterExt as _, Fe32IterExt as _, Hrp};
        let bytes = sealed_maker();
        let old_hrp: String = bytes
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&Hrp::parse("zswapoffer").unwrap())
            .chars()
            .collect();
        assert!(!is_swap_offer(&old_hrp));
        assert!(decode_swap_offer(&old_hrp).is_err());

        let mut corrupted = encode_swap_offer(&bytes);
        let last = corrupted.pop().unwrap();
        corrupted.push(if last == 'q' { 'p' } else { 'q' });
        assert!(decode_swap_offer(&corrupted).is_err());
    }
}
