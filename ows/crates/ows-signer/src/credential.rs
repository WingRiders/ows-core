//! Credential schemes. A credential is a key that another account (a contract)
//! registered as one of its signers: it has no address of its own, and it signs
//! only the statement its verifier checks, which the scheme builds from an
//! authorisation request. The chain and the scheme name select an implementation, see
//! [`crate::chains::credential_scheme`].

use crate::traits::SignerError;
use crate::zeroizing::SecretBytes;
use ows_core::policy::TypedDataContext;
use serde_json::{Map, Value};

/// A credential key, freshly generated or imported.
#[derive(Debug)]
pub struct CredentialKey {
    /// The secret in the scheme's import format.
    pub secret: SecretBytes,
    /// The public key as the verifier registers it.
    pub public_key: String,
}

pub trait CredentialScheme: Send + Sync {
    /// The scheme's name, as credential files record it.
    fn name(&self) -> &'static str;

    /// Generate a key from OS randomness. Credential keys are never derived.
    fn generate(&self) -> Result<CredentialKey, SignerError>;

    /// Accept an existing secret, rejecting any the verifier would not.
    fn import(&self, secret: &[u8]) -> Result<CredentialKey, SignerError>;

    /// Parse an authorisation request strictly and report what policy evaluates.
    fn describe(&self, request: &str) -> Result<TypedDataContext, SignerError>;

    /// Sign the statement the verifier checks for the authorisation request `request`.
    fn sign(&self, secret: &[u8], request: &str) -> Result<Vec<u8>, SignerError>;

    /// Ok(()) when `signature` is a valid signature of `request` under `public_key`, as the verifier checks it.
    fn verify(&self, public_key: &str, request: &str, signature: &[u8]) -> Result<(), SignerError>;

    /// `signature`, made under `public_key`, as the named fields the verifier takes it in.
    /// `ows credential sign --json` prints them and the bindings return them.
    fn signature_fields(
        &self,
        public_key: &str,
        signature: &[u8],
    ) -> Result<Map<String, Value>, SignerError>;

    /// What a new credential needs before its signatures count, such as registering its public key
    /// with the account. Shown after a credential is created or imported.
    fn create_hint(&self) -> Option<&'static str>;

    /// What deleting a credential from the vault leaves in place, such as a registration of its
    /// public key that only the account can remove. Shown before a credential is deleted.
    fn delete_warning(&self) -> Option<&'static str>;
}
