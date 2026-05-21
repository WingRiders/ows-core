use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use crate::{HdDeriver, Mnemonic, SecretBytes};
use cardano_serialization_lib::{
    Address, AddressKind, BaseAddress, Bip32PrivateKey, Credential, EnterpriseAddress, NetworkInfo,
    RewardAddress,
};
use emurgo_cardano_message_signing::builders::{AlgorithmId, COSESign1Builder};
use emurgo_cardano_message_signing::cbor::CBORValue;
use emurgo_cardano_message_signing::utils::ToBytes as EmurgoToBytes;
use emurgo_cardano_message_signing::{
    HeaderMap, Headers, Label, ProtectedHeaderMap, SignedMessage,
};
use ows_core::ChainType;

pub struct CardanoSigner {
    network_id: u8,
}

impl CardanoSigner {
    pub fn mainnet() -> Self {
        Self {
            network_id: NetworkInfo::mainnet().network_id(),
        }
    }

    pub fn preprod() -> Self {
        Self {
            network_id: NetworkInfo::testnet_preprod().network_id(),
        }
    }

    pub fn preview() -> Self {
        Self {
            network_id: NetworkInfo::testnet_preview().network_id(),
        }
    }

    pub fn from_chain_id(chain_id: &str) -> Self {
        match chain_id {
            "cip34:0-1" => Self::preprod(),
            "cip34:0-2" => Self::preview(),
            _ => Self::mainnet(),
        }
    }

    /// CIP-1852 payment key path: `m/1852'/1815'/{account}'/0/{index}`.
    pub fn payment_derivation_path(account: u32, index: u32) -> String {
        format!("m/1852'/1815'/{account}'/0/{index}")
    }

    /// CIP-1852 stake key path: `m/1852'/1815'/{account}'/2/0`.
    pub fn stake_derivation_path(account: u32) -> String {
        format!("m/1852'/1815'/{account}'/2/0")
    }

    /// Account-level prefix: `m/1852'/1815'/{account}'`.
    pub fn account_derivation_path(account: u32) -> String {
        format!("m/1852'/1815'/{account}'")
    }

    fn payment_bip32(key_material: &[u8]) -> Result<Bip32PrivateKey, SignerError> {
        let pay = match key_material.len() {
            ed25519_bip32::XPRV_SIZE => key_material,
            len if len == ed25519_bip32::XPRV_SIZE * 2 => &key_material[..ed25519_bip32::XPRV_SIZE],
            _ => {
                return Err(SignerError::InvalidPrivateKey(format!(
                    "Cardano key material must be 96 (payment) or 192 (payment||stake) bytes, got {}",
                    key_material.len()
                )));
            }
        };
        Bip32PrivateKey::from_bytes(pay).map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
    }

    fn stake_bip32(key_material: &[u8]) -> Result<Option<Bip32PrivateKey>, SignerError> {
        if key_material.len() == ed25519_bip32::XPRV_SIZE * 2 {
            Bip32PrivateKey::from_bytes(&key_material[ed25519_bip32::XPRV_SIZE..])
                .map(Some)
                .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
        } else {
            Ok(None)
        }
    }

    fn base_address_bech32(
        &self,
        pay: &Bip32PrivateKey,
        stake: &Bip32PrivateKey,
    ) -> Result<String, SignerError> {
        let network_id = self.network_id;
        let pay_cred = Credential::from_keyhash(&pay.to_public().to_raw_key().hash());
        let stake_cred = Credential::from_keyhash(&stake.to_public().to_raw_key().hash());
        let base = BaseAddress::new(network_id, &pay_cred, &stake_cred);
        base.to_address()
            .to_bech32(None)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))
    }

    fn enterprise_address_bech32(&self, pay: &Bip32PrivateKey) -> Result<String, SignerError> {
        let network_id = self.network_id;
        let pay_cred = Credential::from_keyhash(&pay.to_public().to_raw_key().hash());
        let ent = EnterpriseAddress::new(network_id, &pay_cred);
        ent.to_address()
            .to_bech32(None)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))
    }

    fn reward_address_bech32(&self, stake: &Bip32PrivateKey) -> Result<String, SignerError> {
        let network_id = self.network_id;
        let stake_cred = Credential::from_keyhash(&stake.to_public().to_raw_key().hash());
        let rew = RewardAddress::new(network_id, &stake_cred);
        rew.to_address()
            .to_bech32(None)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))
    }
}

impl ChainSigner for CardanoSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Cardano
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519Bip32
    }

    fn coin_type(&self) -> u32 {
        1815
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let pay = Self::payment_bip32(private_key)?;
        let stake = Self::stake_bip32(private_key)?;
        match stake.as_ref() {
            Some(s) => self.base_address_bech32(&pay, s),
            None => self.enterprise_address_bech32(&pay),
        }
    }

    fn sign(&self, _private_key: &[u8], _message: &[u8]) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed("not implemented".into()))
    }

    fn sign_message(
        &self,
        private_key: &[u8],
        message: &[u8],
        address: Option<&str>,
    ) -> Result<SignOutput, SignerError> {
        let (address_bytes, sk) = match address {
            Some(a) => {
                let addr = Address::from_bech32(a)
                    .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

                let sk = match addr.kind() {
                    AddressKind::Reward => {
                        let stake = Self::stake_bip32(private_key)?
                            // if the provided address is a reward address, we expect the provided private key to have a stake key
                            .map_or_else(
                                || {
                                    Err(SignerError::InvalidPrivateKey(
                                        "provided private key does not have a stake key"
                                            .to_string(),
                                    ))
                                },
                                Ok,
                            )?;

                        if self.reward_address_bech32(&stake)? != a {
                            return Err(SignerError::AddressMismatch);
                        }

                        stake
                    }
                    AddressKind::Base => {
                        let pay = Self::payment_bip32(private_key)?;
                        let stake = Self::stake_bip32(private_key)?
                            // if the provided address is a base address, we expect the provided private key to have a stake key
                            .map_or_else(
                                || {
                                    Err(SignerError::InvalidPrivateKey(
                                        "provided private key does not have a stake key"
                                            .to_string(),
                                    ))
                                },
                                Ok,
                            )?;

                        if self.base_address_bech32(&pay, &stake)? != a {
                            return Err(SignerError::AddressMismatch);
                        }

                        pay
                    }
                    AddressKind::Enterprise => {
                        let pay = Self::payment_bip32(private_key)?;

                        if self.enterprise_address_bech32(&pay)? != a {
                            return Err(SignerError::AddressMismatch);
                        }

                        pay
                    }
                    _ => {
                        return Err(SignerError::AddressMismatch);
                    }
                };

                (addr.to_bytes(), sk)
            }
            // if the address is not provided, we sign the message with the payment credentials and address derived from the provided private key
            None => {
                let pay = Self::payment_bip32(private_key)?;
                let stake = Self::stake_bip32(private_key)?;
                let addr = Address::from_bech32(&match stake.as_ref() {
                    Some(s) => self.base_address_bech32(&pay, s)?,
                    None => self.enterprise_address_bech32(&pay)?,
                })
                .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

                (addr.to_bytes(), pay)
            }
        };

        let mut protected_headers = HeaderMap::new();
        protected_headers.set_algorithm_id(&AlgorithmId::EdDSA.into());
        protected_headers
            .set_header(
                &Label::new_text(String::from("address")),
                &CBORValue::new_bytes(address_bytes),
            )
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let protected_headers_serialized = ProtectedHeaderMap::new(&protected_headers);
        let headers: Headers = Headers::new(&protected_headers_serialized, &HeaderMap::new());

        let builder = COSESign1Builder::new(&headers, message.to_vec(), false);
        let sig_structure = builder.make_data_to_sign();
        let sig_bytes = EmurgoToBytes::to_bytes(&sig_structure);

        let sig = sk.to_raw_key().sign(&sig_bytes);

        let cose = builder.build(sig.to_bytes());
        let signed = SignedMessage::new_cose_sign1(&cose);
        let signature = EmurgoToBytes::to_bytes(&signed);

        Ok(SignOutput {
            signature,
            recovery_id: None,
            public_key: Some(sk.to_public().to_raw_key().as_bytes()),
        })
    }

    fn sign_transaction(
        &self,
        _private_key: &[u8],
        _tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed("not implemented".into()))
    }

    /// Payment leaf (account 0) for generic single-path key resolution (`decrypt_signing_key`, etc.).
    fn default_derivation_path(&self, index: u32) -> String {
        Self::payment_derivation_path(0, index)
    }

    fn derive_key_material(
        &self,
        mnemonic: &Mnemonic,
        index: u32,
    ) -> Result<SecretBytes, SignerError> {
        let payment_path = CardanoSigner::payment_derivation_path(0, index);
        let stake_path = CardanoSigner::stake_derivation_path(0);
        let curve = self.curve();

        let payment_key =
            HdDeriver::derive_from_mnemonic_cached(mnemonic, "", &payment_path, curve)
                .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
        let stake_key = HdDeriver::derive_from_mnemonic_cached(mnemonic, "", &stake_path, curve)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;

        Ok(SecretBytes::from_slice(
            &[payment_key.expose(), stake_key.expose()].concat(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdDeriver;
    use crate::mnemonic::Mnemonic;
    use hex::FromHex;

    #[test]
    fn test_cip1852_paths() {
        assert_eq!(
            CardanoSigner::payment_derivation_path(0, 0),
            "m/1852'/1815'/0'/0/0"
        );
        assert_eq!(
            CardanoSigner::stake_derivation_path(0),
            "m/1852'/1815'/0'/2/0"
        );
        assert_eq!(
            CardanoSigner::payment_derivation_path(0, 3),
            "m/1852'/1815'/0'/0/3"
        );
        assert_eq!(
            CardanoSigner::account_derivation_path(1),
            "m/1852'/1815'/1'"
        );
    }

    #[test]
    fn test_chain_type_and_curve() {
        let s = CardanoSigner::mainnet();
        assert_eq!(s.chain_type(), ChainType::Cardano);
        assert_eq!(s.curve(), Curve::Ed25519Bip32);
        assert_eq!(s.coin_type(), 1815);
    }

    #[test]
    fn test_default_derivation_path_is_payment() {
        let s = CardanoSigner::mainnet();
        assert_eq!(s.default_derivation_path(0), "m/1852'/1815'/0'/0/0");
        assert_eq!(s.default_derivation_path(5), "m/1852'/1815'/0'/0/5");
    }

    #[test]
    fn derive_base_address_from_12_words() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = s.derive_key_material(&m, 0).unwrap();
        assert_eq!(s.derive_address(&key.expose()).unwrap(), "addr1qyrqjj5nmz8emqexj7yc5wragnk0yfj4wznvjfccmrksxqcj04pscfgjxcvtant3cxg7588twyywwm68nglxaqul8xps7np3y0");
    }

    #[test]
    fn derive_base_address_from_24_words() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase("struggle garbage joke erupt hawk write misery fold hobby shoulder speed movie earth tool medal permit fever wage kid fence off wait order state").unwrap();
        let key = s.derive_key_material(&m, 0).unwrap();
        assert_eq!(s.derive_address(&key.expose()).unwrap(), "addr1q9dfl5qs6jncq6200cxqy7juhw7fm2mk5wm5p0qnx5pmsl80734zn65gc55ecvafkhuxawlnn6wevkmg8dm5kt9vxyys322t44");
    }

    #[test]
    fn derive_enterprise_address_from_12_words() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();

        let payment_path = CardanoSigner::payment_derivation_path(0, 0);
        let payment_key = HdDeriver::derive_from_mnemonic(&m, "", &payment_path, s.curve())
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
            .unwrap();

        let address = s.derive_address(&payment_key.expose()).unwrap();
        assert_eq!(
            address,
            "addr1vyrqjj5nmz8emqexj7yc5wragnk0yfj4wznvjfccmrksxqcx2tst3"
        );
    }

    #[test]
    fn derive_enterprise_address_from_24_words() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "struggle garbage joke erupt hawk write misery fold hobby shoulder speed movie earth tool medal permit fever wage kid fence off wait order state",
        )
        .unwrap();

        let payment_path = CardanoSigner::payment_derivation_path(0, 0);
        let payment_key = HdDeriver::derive_from_mnemonic(&m, "", &payment_path, s.curve())
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
            .unwrap();

        let address = s.derive_address(&payment_key.expose()).unwrap();
        assert_eq!(
            address,
            "addr1v9dfl5qs6jncq6200cxqy7juhw7fm2mk5wm5p0qnx5pmslqy6xjzf"
        );
    }

    #[test]
    fn sign_message_with_none_address() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = s.derive_key_material(&m, 0).unwrap();
        let msg = <Vec<u8>>::from_hex("cafe").unwrap();
        let sig = s.sign_message(&key.expose(), &msg, None).unwrap();

        assert_eq!(hex::encode(sig.signature), "845846a20127676164647265737358390106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed0303127d430c25123618becd71c191ea1ceb7108e76f479a3e6e839f3983a166686173686564f442cafe5840a16c4eb2e963ebd2555292d3dd51bb6ede526ade7e127a8815c940c51a29029931bf5f1b7ce842f12efe25a8aa28037bc9fcb834501aef79ba3df9c0b80ab009");
        assert_eq!(
            hex::encode(sig.public_key.unwrap()),
            "65a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128"
        );
    }

    #[test]
    fn sign_message_with_base_address() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = s.derive_key_material(&m, 0).unwrap();
        let msg = <Vec<u8>>::from_hex("cafe").unwrap();
        let sig = s.sign_message(&key.expose(), &msg, Some("addr1qyrqjj5nmz8emqexj7yc5wragnk0yfj4wznvjfccmrksxqcj04pscfgjxcvtant3cxg7588twyywwm68nglxaqul8xps7np3y0")).unwrap();

        assert_eq!(hex::encode(sig.signature), "845846a20127676164647265737358390106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed0303127d430c25123618becd71c191ea1ceb7108e76f479a3e6e839f3983a166686173686564f442cafe5840a16c4eb2e963ebd2555292d3dd51bb6ede526ade7e127a8815c940c51a29029931bf5f1b7ce842f12efe25a8aa28037bc9fcb834501aef79ba3df9c0b80ab009");
        assert_eq!(
            hex::encode(sig.public_key.unwrap()),
            "65a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128"
        );
    }

    #[test]
    fn sign_message_with_enterprise_address() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = s.derive_key_material(&m, 0).unwrap();
        let msg = <Vec<u8>>::from_hex("cafe").unwrap();
        let sig = s
            .sign_message(
                &key.expose(),
                &msg,
                Some("addr1vyrqjj5nmz8emqexj7yc5wragnk0yfj4wznvjfccmrksxqcx2tst3"),
            )
            .unwrap();

        assert_eq!(hex::encode(sig.signature), "84582aa201276761646472657373581d6106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed0303a166686173686564f442cafe58401bb30176a6f48c3eefd4f659afd29c98e4668e4d5676474b7e4497e960e6a8e79860fd3bdb41093e448fc62aa74291490b683adb579e6a3e17a89d0b329ea70f");
        assert_eq!(
            hex::encode(sig.public_key.unwrap()),
            "65a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128"
        );
    }

    #[test]
    fn sign_message_with_reward_address() {
        let s = CardanoSigner::mainnet();
        let m = Mnemonic::from_phrase(
            "jelly wolf grass equip diagram mixed bottom speed luggage venture stool end",
        )
        .unwrap();
        let key = s.derive_key_material(&m, 0).unwrap();
        let msg = <Vec<u8>>::from_hex("cafe").unwrap();
        let sig = s
            .sign_message(
                &key.expose(),
                &msg,
                Some("stake1uyf86scvy5frvx97e4cury02rn4hzz88dare50nwsw0nnqcxw9kf5"),
            )
            .unwrap();

        assert_eq!(hex::encode(sig.signature), "84582aa201276761646472657373581de1127d430c25123618becd71c191ea1ceb7108e76f479a3e6e839f3983a166686173686564f442cafe58401152563eb2dd6dd9775b1e8cd21d829edb93851aba7705156b68c6b9cde9634e9f85f434287172129d8f49c655876ac64293d5ad8370247a5b04e9bdf675d505");
        assert_eq!(
            hex::encode(sig.public_key.unwrap()),
            "097cdc1da25a445eda8db6c3f0a3c3ba86c6a9555df0b4010f4d042ed94c2206"
        );
    }
}
