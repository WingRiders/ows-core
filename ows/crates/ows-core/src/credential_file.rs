use crate::chain::ChainType;
use serde::{Deserialize, Serialize};

/// The credential file format this build reads and writes. A file of any other version is
/// refused, so that a field a later version adds, such as a restriction, is never dropped.
pub const CREDENTIAL_FILE_VERSION: u32 = 2;

/// A key that some other account registered as one of its signers, stored at
/// `~/.ows/credentials/<id>.json`. Unlike a wallet it has no accounts and is never derived.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub ows_version: u32,
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub chain: ChainType,
    /// Names the credential scheme within the chain, e.g. which signature the verifier checks.
    pub scheme: String,
    /// Public key in the scheme's canonical text encoding.
    pub public_key: String,
    pub origin: CredentialOrigin,
    pub crypto: serde_json::Value,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

/// Whether OWS generated the key or it was brought in from outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOrigin {
    Generated,
    Imported,
}

impl CredentialOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialOrigin::Generated => "generated",
            CredentialOrigin::Imported => "imported",
        }
    }
}

impl Credential {
    pub fn new(
        id: String,
        name: String,
        chain: ChainType,
        scheme: String,
        public_key: String,
        origin: CredentialOrigin,
        crypto: serde_json::Value,
    ) -> Self {
        Credential {
            ows_version: CREDENTIAL_FILE_VERSION,
            id,
            name,
            created_at: chrono::Utc::now().to_rfc3339(),
            chain,
            scheme,
            public_key,
            origin,
            crypto,
            metadata: serde_json::Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy() -> Credential {
        Credential::new(
            "cred-id".to_string(),
            "device".to_string(),
            ChainType::Midnight,
            "jubjub".to_string(),
            "ab".repeat(64),
            CredentialOrigin::Generated,
            serde_json::json!({"cipher": "aes-256-gcm"}),
        )
    }

    #[test]
    fn credential_serde_round_trip() {
        let c = dummy();
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["origin"], "generated");
        assert_eq!(json["chain"], "midnight");
        let back: Credential = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "cred-id");
        assert_eq!(back.name, "device");
        assert_eq!(back.ows_version, 2);
        assert_eq!(back.scheme, "jubjub");
        assert_eq!(back.origin, CredentialOrigin::Generated);
        assert_eq!(back.chain, ChainType::Midnight);
    }

    #[test]
    fn origin_as_str_matches_the_serialized_form() {
        for origin in [CredentialOrigin::Generated, CredentialOrigin::Imported] {
            assert_eq!(serde_json::json!(origin), origin.as_str());
        }
    }

    #[test]
    fn credential_metadata_omitted_when_null() {
        let json = serde_json::to_value(dummy()).unwrap();
        assert!(json.get("metadata").is_none());
    }
}
