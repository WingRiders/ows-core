//! JubJub Schnorr credentials (MIP-0013): the device keys a Midnight account
//! contract, such as a Passport account, registers as its signers. OWS never signs
//! raw bytes with them: it rebuilds, from an authorisation request, the challenge
//! the contract's gated circuit recomputes, and signs that.

use crate::credential::{CredentialKey, CredentialScheme};
use crate::traits::SignerError;
use crate::zeroizing::SecretBytes;
use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value as FabValue, ValueAtom,
};
use midnight_base_crypto::hash::PersistentHashWriter;
use midnight_base_crypto::BinaryHashRepr;
use midnight_serialize::Deserializable;
use ows_core::policy::TypedDataContext;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha512};
use std::collections::HashSet;
use std::fmt;
use transient_crypto::curve::{embedded, EmbeddedFr, EmbeddedGroupAffine, Fr};
use transient_crypto::fab::ValueReprAlignedValue;
use zeroize::Zeroizing;

const SIGNATURE_LEN: usize = 104;
const MAX_STRUCT_DEPTH: usize = 8;
// A challenge lands below r_J about once in 17 grind nonces (MIP-0013 §5.2).
const MAX_GRIND_NONCE: u64 = 10_000;
const NONCE_TAG: &[u8] = b"ows:credential:jubjub:nonce:v1";
// Credentials sign device authorisations only. Other DST families, such as
// grants, stay unsigned until they are added deliberately.
const AUTH_SCHEME: &str = "midnight:account:auth:v1";

/// Schnorr over the prime-order JubJub subgroup, as MIP-0013 specifies it.
///
/// The secret is sk as 32 big-endian bytes, the public key x ‖ y in hex, and a
/// signature R.x ‖ R.y ‖ s ‖ grind_nonce (32 + 32 + 32 + 8 big-endian bytes).
pub struct JubjubCredential;

impl CredentialScheme for JubjubCredential {
    fn name(&self) -> &'static str {
        "jubjub"
    }

    fn generate(&self) -> Result<CredentialKey, SignerError> {
        let mut candidate = Zeroizing::new([0u8; 32]);
        loop {
            os_random(&mut candidate[..])?;
            // r_J < 2^252: clearing the top four bits keeps nine draws in ten, and
            // rejecting the rest keeps sk exactly uniform in [1, r_J).
            candidate[0] &= 0x0f;
            if let Ok(sk) = secret_scalar(&candidate[..]) {
                return credential_key(&candidate[..], &sk);
            }
        }
    }

    fn import(&self, secret: &[u8]) -> Result<CredentialKey, SignerError> {
        let sk = secret_scalar(secret)?;
        credential_key(secret, &sk)
    }

    fn describe(&self, request: &str) -> Result<TypedDataContext, SignerError> {
        let parsed = Request::parse(request)?;
        Ok(TypedDataContext {
            verifying_contract: Some(hex::encode(parsed.account)),
            domain_chain_id: None,
            primary_type: parsed.circuit,
            domain_name: Some(AUTH_SCHEME.to_string()),
            domain_version: None,
            raw_json: request.to_string(),
        })
    }

    fn sign(&self, secret: &[u8], request: &str) -> Result<Vec<u8>, SignerError> {
        let sk = secret_scalar(secret)?;
        let request = Request::parse(request)?;
        let pk = EmbeddedGroupAffine::generator() * *sk;
        let r = hedged_nonce(secret, &request.nonce_input(&pk)?)?;
        let big_r = EmbeddedGroupAffine::generator() * *r;
        for grind in 0..MAX_GRIND_NONCE {
            let Some(c) = EmbeddedFr::from_le_bytes(&request.challenge(&big_r, &pk, grind)?) else {
                continue;
            };
            let s = *r + c * *sk;
            let mut signature = Vec::with_capacity(SIGNATURE_LEN);
            signature.extend_from_slice(&encode_point(&big_r)?);
            signature.extend_from_slice(&to_be(s.as_le_bytes()));
            signature.extend_from_slice(&grind.to_be_bytes());
            return Ok(signature);
        }
        Err(SignerError::SigningFailed(format!(
            "no challenge below r_J within {MAX_GRIND_NONCE} grind nonces"
        )))
    }

    fn verify(&self, public_key: &str, request: &str, signature: &[u8]) -> Result<(), SignerError> {
        let request = Request::parse(request)?;
        let pk = point_from_be(&hex_str("public key", public_key, 64)?)
            .ok_or_else(|| invalid("public key is not a JubJub subgroup point"))?;
        // The contract rejects a small-order key before its equation; in the
        // prime-order subgroup the identity is the only one.
        if pk.is_identity() {
            return Err(invalid("public key has small order"));
        }
        check_signature_len(signature)?;
        let big_r = point_from_be(&signature[..64])
            .ok_or_else(|| invalid("signature R is not a JubJub subgroup point"))?;
        let s = scalar_from_be(&signature[64..96])
            .ok_or_else(|| invalid("signature s is not below r_J"))?;
        let grind = u64::from_be_bytes(signature[96..].try_into().expect("8 bytes"));
        let c = EmbeddedFr::from_le_bytes(&request.challenge(&big_r, &pk, grind)?)
            .ok_or_else(|| invalid("challenge is not below r_J"))?;
        if EmbeddedGroupAffine::generator() * s == big_r + pk * c {
            Ok(())
        } else {
            Err(invalid("signature does not verify"))
        }
    }

    /// The signature's parts, named after MIP-0013's: the key and R as x ‖ y, s and the
    /// grind nonce, beside the request's scheme identifier.
    fn signature_fields(
        &self,
        public_key: &str,
        signature: &[u8],
    ) -> Result<Map<String, Value>, SignerError> {
        let pk = hex_str("public key", public_key, 64)?;
        check_signature_len(signature)?;
        let grind = u64::from_be_bytes(signature[96..].try_into().expect("8 bytes"));
        Ok(Map::from_iter([
            ("scheme".to_string(), Value::from(AUTH_SCHEME)),
            ("pk".to_string(), Value::from(hex::encode(pk))),
            (
                "sigR".to_string(),
                Value::from(hex::encode(&signature[..64])),
            ),
            (
                "sigS".to_string(),
                Value::from(hex::encode(&signature[64..96])),
            ),
            ("grindNonce".to_string(), Value::from(grind)),
        ]))
    }

    fn create_hint(&self) -> Option<&'static str> {
        Some(
            "Enrol this public key on the account contract before signing with it (on a Passport account: activate_initial_device_with_jubjub for the first device, add_device_with_jubjub after it).",
        )
    }

    fn delete_warning(&self) -> Option<&'static str> {
        Some(
            "This key stays enrolled on any account contract that registered it until the device is removed from that account.",
        )
    }
}

fn invalid(message: impl Into<String>) -> SignerError {
    SignerError::InvalidMessage(message.into())
}

fn check_signature_len(signature: &[u8]) -> Result<(), SignerError> {
    if signature.len() == SIGNATURE_LEN {
        Ok(())
    } else {
        Err(invalid(format!(
            "a signature is {SIGNATURE_LEN} bytes, got {}",
            signature.len()
        )))
    }
}

fn os_random(bytes: &mut [u8]) -> Result<(), SignerError> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|e| SignerError::SigningFailed(format!("OS randomness is unavailable: {e}")))
}

/// MIP-0013 accepts only 1 ≤ sk < r_J (AUTH-7), given as 32 big-endian bytes.
fn secret_scalar(secret: &[u8]) -> Result<Zeroizing<EmbeddedFr>, SignerError> {
    let out_of_range = || {
        SignerError::InvalidPrivateKey(
            "a JubJub credential key is a 32-byte big-endian scalar in [1, r_J)".into(),
        )
    };
    let be: &[u8; 32] = secret.try_into().map_err(|_| out_of_range())?;
    let mut le = Zeroizing::new(*be);
    le.reverse();
    let sk = Zeroizing::new(EmbeddedFr::from_le_bytes(&le[..]).ok_or_else(out_of_range)?);
    if *sk == EmbeddedFr::from(0_u64) {
        return Err(out_of_range());
    }
    Ok(sk)
}

fn credential_key(secret: &[u8], sk: &EmbeddedFr) -> Result<CredentialKey, SignerError> {
    let pk = EmbeddedGroupAffine::generator() * *sk;
    Ok(CredentialKey {
        secret: SecretBytes::from_slice(secret),
        public_key: hex::encode(encode_point(&pk)?),
    })
}

/// MIP-0013 §5.3 wants a nonce that is never reused and never predictable, and
/// recommends hedging: sk and the request keep it secret when the OS RNG is weak,
/// and the fresh bytes keep one request signed twice from repeating it.
fn hedged_nonce(secret: &[u8], request: &[u8]) -> Result<Zeroizing<EmbeddedFr>, SignerError> {
    let mut fresh = Zeroizing::new([0u8; 32]);
    os_random(&mut fresh[..])?;
    let mut wide = Zeroizing::new([0u8; 64]);
    Sha512::new()
        .chain_update(NONCE_TAG)
        .chain_update(secret)
        .chain_update(request)
        .chain_update(&fresh[..])
        .finalize_into(GenericArray::from_mut_slice(&mut wide[..]));
    let r = Zeroizing::new(EmbeddedFr(embedded::Scalar::from_bytes_wide(&wide)));
    if *r == EmbeddedFr::from(0_u64) {
        return Err(SignerError::SigningFailed(
            "signing nonce reduced to zero".into(),
        ));
    }
    Ok(r)
}

/// Any JSON value, refused if an object in it repeats a key. Policies read the request from
/// `raw_json` with a parser of their own, and parsers disagree on which of two equal keys wins.
struct UniqueKeys;

impl<'de> Deserialize<'de> for UniqueKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueKeys)
    }
}

impl<'de> Visitor<'de> for UniqueKeys {
    type Value = UniqueKeys;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self, E> {
        Ok(UniqueKeys)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self, E> {
        Ok(UniqueKeys)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self, E> {
        Ok(UniqueKeys)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self, E> {
        Ok(UniqueKeys)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self, E> {
        Ok(UniqueKeys)
    }

    fn visit_unit<E>(self) -> Result<Self, E> {
        Ok(UniqueKeys)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self, A::Error> {
        while seq.next_element::<UniqueKeys>()?.is_some() {}
        Ok(UniqueKeys)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self, A::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if keys.contains(&key) {
                return Err(de::Error::custom(format!(
                    "key `{key}` appears twice in one object"
                )));
            }
            map.next_value::<UniqueKeys>()?;
            keys.insert(key);
        }
        Ok(UniqueKeys)
    }
}

/// The authorisation request as it arrives, in MIP-0013's terms: the values the
/// challenge covers, in the challenge's order, each typed for its width.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RequestJson {
    scheme: String,
    account: String,
    circuit: String,
    /// The circuit's arguments in declaration order, without the authorising material
    /// (`pk`, `use_counter` and the signature).
    args: Vec<Value>,
    /// The values the circuit's witnesses return, in invocation order.
    witnesses: Vec<Value>,
    auth_nonce: Value,
}

/// A checked request, with the parts of the challenge preimage that do not depend
/// on the signature already encoded.
struct Request {
    circuit: String,
    account: [u8; 32],
    /// `[DST, self]`, ahead of R and pk.
    head: Fab,
    /// `[...args, ...witness_values, auth_nonce]`, after them.
    tail: Fab,
}

impl Request {
    fn parse(json: &str) -> Result<Self, SignerError> {
        serde_json::from_str::<UniqueKeys>(json).map_err(|e| invalid(format!("request: {e}")))?;
        let request: RequestJson =
            serde_json::from_str(json).map_err(|e| invalid(format!("request: {e}")))?;
        if request.scheme != AUTH_SCHEME {
            return Err(invalid(format!(
                "only device authorisations, scheme {AUTH_SCHEME}, are signed"
            )));
        }
        if !is_identifier(&request.circuit) {
            return Err(invalid(format!(
                "circuit {:?} is not a Compact identifier",
                request.circuit
            )));
        }
        let account: [u8; 32] = hex_str("account", &request.account, 32)?
            .try_into()
            .expect("32 bytes");
        let auth_nonce = uint("authNonce", &request.auth_nonce, 64)?;

        let mut head = Fab::default();
        head.bytes(&dst(&format!("{AUTH_SCHEME}:{}", request.circuit))?);
        head.bytes(&account);
        let mut tail = Fab::default();
        for (list, values) in [("args", &request.args), ("witnesses", &request.witnesses)] {
            for (i, value) in values.iter().enumerate() {
                encode_value(value, &format!("{list}[{i}]"), 0, &mut tail)?;
            }
        }
        tail.uint(64, auth_nonce);
        Ok(Request {
            circuit: request.circuit,
            account,
            head,
            tail,
        })
    }

    /// MIP-0013 §5.1: persistentHash of
    /// `[DST, self, R, pk, ...args, ...witness_values, auth_nonce, grind_nonce]`.
    fn challenge(
        &self,
        big_r: &EmbeddedGroupAffine,
        pk: &EmbeddedGroupAffine,
        grind: u64,
    ) -> Result<[u8; 32], SignerError> {
        let mut preimage = self.head.clone();
        preimage.point(big_r)?;
        preimage.point(pk)?;
        preimage.extend(&self.tail);
        preimage.uint(64, grind.into());
        persistent_hash(preimage)
    }

    /// The nonce's canonical request bytes: the challenge preimage without R and
    /// the grind nonce, which both depend on the nonce.
    fn nonce_input(&self, pk: &EmbeddedGroupAffine) -> Result<Vec<u8>, SignerError> {
        let mut bytes = self.head.clone();
        bytes.point(pk)?;
        bytes.extend(&self.tail);
        Ok(bytes.into_repr()?.binary_vec())
    }
}

enum Primitive {
    Bytes(usize),
    Uint(u32),
    Point,
}

fn primitive(ty: &str) -> Option<Primitive> {
    match ty {
        // Compact's standard library wraps each of these around a single Bytes<32>.
        "ContractAddress" | "UserAddress" | "ZswapCoinPublicKey" => Some(Primitive::Bytes(32)),
        "JubjubPoint" => Some(Primitive::Point),
        _ => {
            if let Some(n) = size_parameter(ty, "Bytes<") {
                Some(Primitive::Bytes(n as usize))
            } else {
                size_parameter(ty, "Uint<")
                    .filter(|bits| *bits <= 128)
                    .map(Primitive::Uint)
            }
        }
    }
}

fn size_parameter(ty: &str, prefix: &str) -> Option<u32> {
    let n = ty.strip_prefix(prefix)?.strip_suffix('>')?;
    if n.starts_with('0') || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

// The circuit tag is `scheme:circuit`, zero-padded, so a `:` or NUL in a circuit
// name would let two requests, described as different circuits, share one DST.
fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Appends one value: a primitive at its type's width, or a struct's fields in
/// order, struct fields recursively, as a Compact tuple of the same fields would
/// lay them out. `depth` counts the structs around the value.
fn encode_value(value: &Value, path: &str, depth: usize, out: &mut Fab) -> Result<(), SignerError> {
    let object = value.as_object().ok_or_else(|| {
        invalid(format!(
            "{path}: expected an object with `type` and either `value` or `fields`"
        ))
    })?;
    if let Some(key) = object
        .keys()
        .find(|key| !matches!(key.as_str(), "type" | "value" | "fields"))
    {
        return Err(invalid(format!(
            "{path}.{key} is not allowed: a value has `type` and either `value` or `fields`"
        )));
    }
    let ty = object
        .get("type")
        .ok_or_else(|| invalid(format!("{path}.type is missing")))?
        .as_str()
        .ok_or_else(|| invalid(format!("{path}.type: expected a string")))?;
    match (object.get("value"), object.get("fields")) {
        (Some(_), Some(_)) => Err(invalid(format!("{path} has both `value` and `fields`"))),
        (None, None) => Err(invalid(format!("{path} has neither `value` nor `fields`"))),
        (Some(value), None) => encode_primitive(ty, value, path, out),
        (None, Some(fields)) => encode_struct(ty, fields, path, depth + 1, out),
    }
}

fn encode_primitive(ty: &str, value: &Value, path: &str, out: &mut Fab) -> Result<(), SignerError> {
    match primitive(ty).ok_or_else(|| invalid(format!("{path}: unsupported type `{ty}`")))? {
        Primitive::Bytes(len) => out.bytes(&hex_value(path, value, len)?),
        Primitive::Uint(bits) => out.uint(bits, uint(path, value, bits)?),
        Primitive::Point => out.point(
            &point_from_be(&hex_value(path, value, 64)?)
                .ok_or_else(|| invalid(format!("{path}: not a JubJub subgroup point")))?,
        )?,
    }
    Ok(())
}

fn encode_struct(
    name: &str,
    fields: &Value,
    path: &str,
    depth: usize,
    out: &mut Fab,
) -> Result<(), SignerError> {
    if primitive(name).is_some() {
        return Err(invalid(format!(
            "{path}: `{name}` is a primitive type, which takes `value`, not `fields`"
        )));
    }
    if !is_identifier(name) {
        return Err(invalid(format!(
            "{path}: struct name {name:?} is not a Compact identifier"
        )));
    }
    if depth > MAX_STRUCT_DEPTH {
        return Err(invalid(format!(
            "{path}: structs nest deeper than {MAX_STRUCT_DEPTH}"
        )));
    }
    let fields = fields
        .as_array()
        .ok_or_else(|| invalid(format!("{path}.fields: expected an array of values")))?;
    for (i, field) in fields.iter().enumerate() {
        encode_value(field, &format!("{path}.fields[{i}]"), depth, out)?;
    }
    Ok(())
}

fn hex_value(path: &str, value: &Value, len: usize) -> Result<Vec<u8>, SignerError> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(format!("{path}: expected a hex string")))?;
    hex_str(path, text, len)
}

fn hex_str(path: &str, text: &str, len: usize) -> Result<Vec<u8>, SignerError> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let bytes = hex::decode(digits).map_err(|_| invalid(format!("{path}: not hex")))?;
    if bytes.len() != len {
        return Err(invalid(format!(
            "{path}: expected {len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn uint(path: &str, value: &Value, bits: u32) -> Result<u128, SignerError> {
    let parsed = match value {
        Value::Number(n) => n.as_u64().map(u128::from),
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        _ => None,
    };
    parsed
        .filter(|v| bits >= 128 || v >> bits == 0)
        .ok_or_else(|| invalid(format!("{path}: expected a Uint<{bits}>")))
}

fn to_be(mut le: Vec<u8>) -> Vec<u8> {
    le.reverse();
    le
}

fn coordinates(point: &EmbeddedGroupAffine) -> Result<(Fr, Fr), SignerError> {
    point
        .x()
        .zip(point.y())
        .ok_or_else(|| SignerError::SigningFailed("point has no affine coordinates".into()))
}

/// x ‖ y as big-endian field elements, the form the contract runtime prints.
fn encode_point(point: &EmbeddedGroupAffine) -> Result<[u8; 64], SignerError> {
    let (x, y) = coordinates(point)?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&to_be(x.as_le_bytes()));
    out[32..].copy_from_slice(&to_be(y.as_le_bytes()));
    Ok(out)
}

/// Reads x ‖ y back, accepting only points of the prime-order subgroup.
fn point_from_be(bytes: &[u8]) -> Option<EmbeddedGroupAffine> {
    let x = Fr::from_le_bytes(&to_be(bytes[..32].to_vec()))?;
    let y = Fr::from_le_bytes(&to_be(bytes[32..].to_vec()))?;
    // `EmbeddedGroupAffine::new` panics outside the subgroup, so untrusted
    // coordinates go through the ledger's checked decoder, which takes JubJub's
    // compressed form (y, with the parity of x in the top bit) and rejects points
    // off the curve or outside the subgroup. Comparing x after decompression
    // rejects an x that does not belong to y.
    let mut compressed = y.as_le_bytes();
    compressed[31] |= (x.as_le_bytes()[0] & 1) << 7;
    let point = EmbeddedGroupAffine::deserialize(&mut compressed.as_slice(), 0).ok()?;
    (point.x() == Some(x) && point.y() == Some(y)).then_some(point)
}

fn scalar_from_be(bytes: &[u8]) -> Option<EmbeddedFr> {
    EmbeddedFr::from_le_bytes(&to_be(bytes.to_vec()))
}

/// MIP-0013 §5.1 as amended by midnight-improvement-proposals#249: the DST is
/// persistentHash<[Bytes<64>]> of the tag zero-padded to 64 bytes.
fn dst(tag: &str) -> Result<[u8; 32], SignerError> {
    if tag.len() > 64 {
        return Err(invalid(format!(
            "circuit tag `{tag}` is longer than 64 bytes"
        )));
    }
    let mut padded = [0u8; 64];
    padded[..tag.len()].copy_from_slice(tag.as_bytes());
    let mut value = Fab::default();
    value.bytes(&padded);
    persistent_hash(value)
}

/// Compact's persistentHash: SHA-256 over the ledger's binary representation of a
/// field-aligned value.
fn persistent_hash(value: Fab) -> Result<[u8; 32], SignerError> {
    let mut writer = PersistentHashWriter::new();
    value.into_repr()?.binary_repr(&mut writer);
    Ok(writer.finalize().0)
}

/// A Compact value in the ledger's field-aligned binary encoding: one atom per
/// Bytes or Uint value, two field atoms per point.
#[derive(Clone, Default)]
struct Fab {
    atoms: Vec<ValueAtom>,
    alignment: Vec<AlignmentSegment>,
}

impl Fab {
    fn push(&mut self, atom: AlignmentAtom, le_bytes: Vec<u8>) {
        self.atoms.push(ValueAtom(le_bytes).normalize());
        self.alignment.push(AlignmentSegment::Atom(atom));
    }

    fn bytes(&mut self, bytes: &[u8]) {
        let length = u32::try_from(bytes.len()).expect("hex-decoded length fits u32");
        self.push(AlignmentAtom::Bytes { length }, bytes.to_vec());
    }

    fn uint(&mut self, bits: u32, value: u128) {
        let length = bits.div_ceil(8);
        self.push(
            AlignmentAtom::Bytes { length },
            value.to_le_bytes()[..length as usize].to_vec(),
        );
    }

    fn point(&mut self, point: &EmbeddedGroupAffine) -> Result<(), SignerError> {
        let (x, y) = coordinates(point)?;
        self.push(AlignmentAtom::Field, x.as_le_bytes());
        self.push(AlignmentAtom::Field, y.as_le_bytes());
        Ok(())
    }

    fn extend(&mut self, other: &Fab) {
        self.atoms.extend_from_slice(&other.atoms);
        self.alignment.extend_from_slice(&other.alignment);
    }

    fn into_repr(self) -> Result<ValueReprAlignedValue, SignerError> {
        AlignedValue::new(FabValue(self.atoms), Alignment(self.alignment))
            .map(ValueReprAlignedValue)
            .ok_or_else(|| SignerError::SigningFailed("value does not fit its alignment".into()))
    }
}

#[cfg(test)]
mod tests;
