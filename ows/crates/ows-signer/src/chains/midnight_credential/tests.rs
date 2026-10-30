use super::*;
use serde_json::{json, Value};
use transient_crypto::curve::{EmbeddedFr, Fr};

// Vectors from the compiled Passport account contract: its pure circuits
// challenge_withdraw_unshielded_with_jubjub and challenge_withdraw_shielded_with_jubjub
// evaluated for pk = 0x0123456789abcdef·G and R = 0x77·G, and both points as the
// contract runtime encodes them.
const ACCOUNT: &str = "a19612afc371b1a4d2fc2410377da895ff7ca406e74449b75dcc32a2b6df7964";
const COLOR: &str = "5cd36fe5ed159246257b476bb67bc8266290581ef3844fcabd7c134b3f8b03ea";
const RECIPIENT: &str = "b0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9e00";
const COIN_NONCE: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
const PK_X: &str = "6d8d5ee89b2ace73f44ee9709edb409e7577141965aa793f5c7a076f1e229c38";
const PK_Y: &str = "64a8306fd5adc424dc1d677c9cbf195d630cefe1060fc9b74f2e63394e03672f";
const SIG_R_X: &str = "630b5506a892f4224e8433bce971e593a326a39a38d184eb687746141616e682";
const SIG_R_Y: &str = "3559d886870d94fddb96e1e306b2704936356efd0f9b0e467467df53592736c8";

// Signatures by sk = 0x0123456789abcdef over unshielded(), shielded() and with_point().
const SIGNATURES: [&str; 3] = [
    "059473cd2da8aa240515ee200cabfb9c23493df53614f92cbd665b43ca6de116303a5d32d7f716dad0d8919ea739ac81c65ee71c286907d294ad58f66062642008a806e8cb01e1d82ef21ea8e4c33d0a01f1ee0f11b52548d7dc63a37ab8a9570000000000000001",
    "2ec9ef3f0b4041d71a98946a699e656d3a291e2236eddf7ea93517bb151469ef5302a3e42447d19905eb4b90b296f9ebedeb77af0f930d12657e1dea8a0c1e90031f5a397b6f1c28ac570e8b8e4def51abc2e82ae74e461d2be5d80eb9bd40b60000000000000004",
    "022db9e6c624deb1809f03ce951adc3b38b909117d64545831daff173a44862b38b00be908082a216fc9d9f18f81cbdcec3daa3ce67f4682d80348bb3987c38908f78273c349c370443109b06b578679876f9cc301c8cace783cef9ac36b2abc0000000000000016",
];

const R_J: &str = "0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7";

fn unshielded() -> Value {
    json!({
        "scheme": "midnight:account:auth:v1",
        "account": ACCOUNT,
        "circuit": "withdraw_unshielded",
        "args": [
            {"type": "Bytes<32>", "value": COLOR},
            {"type": "Uint<128>", "value": "3000000"},
            {"type": "UserAddress", "value": format!("0x{RECIPIENT}")}
        ],
        "witnesses": [],
        "authNonce": "3"
    })
}

fn shielded() -> Value {
    json!({
        "scheme": "midnight:account:auth:v1",
        "account": ACCOUNT,
        "circuit": "withdraw_shielded",
        "args": [
            {"type": "ZswapCoinPublicKey", "value": RECIPIENT},
            {"type": "Bytes<32>", "value": COLOR},
            {"type": "Uint<128>", "value": "150000"}
        ],
        "witnesses": [
            {"type": "QualifiedShieldedCoinInfo", "fields": [
                {"type": "Bytes<32>", "value": COIN_NONCE},
                {"type": "Bytes<32>", "value": COLOR},
                {"type": "Uint<128>", "value": "400000"},
                {"type": "Uint<64>", "value": "66636"}
            ]}
        ],
        "authNonce": 3
    })
}

// No account circuit takes a JubjubPoint argument yet; this one exercises the encoding.
fn with_point() -> Value {
    json!({
        "scheme": "midnight:account:auth:v1",
        "account": ACCOUNT,
        "circuit": "approve_key",
        "args": [
            {"type": "JubjubPoint", "value": format!("{PK_X}{PK_Y}")},
            {"type": "Uint<32>", "value": 7}
        ],
        "witnesses": [],
        "authNonce": 0
    })
}

/// A request whose only argument is `depth` structs, one inside the next.
fn nested(depth: usize) -> Value {
    let mut value = json!({"type": "Uint<8>", "value": 1});
    for level in (1..=depth).rev() {
        value = json!({"type": format!("L{level}"), "fields": [value]});
    }
    json!({
        "scheme": "midnight:account:auth:v1",
        "account": ACCOUNT,
        "circuit": "nest",
        "args": [value],
        "witnesses": [],
        "authNonce": 0
    })
}

fn with(mut request: Value, edit: impl FnOnce(&mut Value)) -> Value {
    edit(&mut request);
    request
}

fn without(request: Value, key: &str) -> Value {
    with(request, |r| {
        r.as_object_mut().unwrap().remove(key).unwrap();
    })
}

/// The challenge the compiled contract computes for `request` at grind nonce 0.
fn contract_challenge(request: &Value) -> [u8; 32] {
    let pk = EmbeddedGroupAffine::generator() * EmbeddedFr::from(0x0123_4567_89ab_cdef_u64);
    let big_r = EmbeddedGroupAffine::generator() * EmbeddedFr::from(0x77_u64);
    Request::parse(&request.to_string())
        .unwrap()
        .challenge(&big_r, &pk, 0)
        .unwrap()
}

fn secret(scalar: u64) -> [u8; 32] {
    let mut be = [0u8; 32];
    be[24..].copy_from_slice(&scalar.to_be_bytes());
    be
}

fn le(be: &[u8]) -> Vec<u8> {
    be.iter().rev().copied().collect()
}

fn be_scalar(be: &[u8]) -> EmbeddedFr {
    EmbeddedFr::from_le_bytes(&le(be)).unwrap()
}

fn be_field(be: &[u8]) -> Fr {
    Fr::from_le_bytes(&le(be)).unwrap()
}

fn point_hex(point: &EmbeddedGroupAffine) -> String {
    let x = le(&point.x().unwrap().as_le_bytes());
    let y = le(&point.y().unwrap().as_le_bytes());
    format!("{}{}", hex::encode(x), hex::encode(y))
}

#[test]
fn points_encode_as_the_contract_runtime_does() {
    for (scalar, x, y) in [
        (0x0123_4567_89ab_cdef, PK_X, PK_Y),
        (0x77, SIG_R_X, SIG_R_Y),
    ] {
        let key = JubjubCredential.import(&secret(scalar)).unwrap();
        assert_eq!(key.public_key, format!("{x}{y}"));
    }
}

#[test]
fn challenges_match_the_compiled_contract() {
    let pk = EmbeddedGroupAffine::generator() * EmbeddedFr::from(0x0123_4567_89ab_cdef_u64);
    let big_r = EmbeddedGroupAffine::generator() * EmbeddedFr::from(0x77_u64);
    for (request, grind, expected) in [
        (
            unshielded(),
            0,
            "9ae1dab88cd51bb0a3d21490d34d0b3fba43b56327c8c05d407051fcb1218305",
        ),
        (
            shielded(),
            0,
            "ee354a899d38b2501b2db0f211e521451a3c4e103cc4575714373ad4a64746e0",
        ),
        (
            unshielded(),
            5,
            "347c021ffbb473bd3b96fe50cb4192e3db680e86895af33c3a1c28572ebabf0e",
        ),
        (
            shielded(),
            5,
            "e61fdd29185232e757fe5d929ee73dc4e999ce8c889e2729d8d21b0dce93a92f",
        ),
    ] {
        let request = Request::parse(&request.to_string()).unwrap();
        assert_eq!(
            hex::encode(request.challenge(&big_r, &pk, grind).unwrap()),
            expected,
            "{} grind {grind}",
            request.circuit
        );
    }
}

#[test]
fn recorded_signatures_verify() {
    let key = JubjubCredential
        .import(&secret(0x0123_4567_89ab_cdef))
        .unwrap();
    for (request, signature) in [unshielded(), shielded(), with_point()]
        .into_iter()
        .zip(SIGNATURES)
    {
        JubjubCredential
            .verify(
                &key.public_key,
                &request.to_string(),
                &hex::decode(signature).unwrap(),
            )
            .unwrap();
    }
}

#[test]
fn the_challenge_covers_bytes_not_value_boundaries_or_types() {
    let split = with(unshielded(), |r| {
        let args = r["args"].as_array_mut().unwrap();
        args[0] = json!({"type": "Bytes<16>", "value": &COLOR[..32]});
        args.insert(1, json!({"type": "Bytes<16>", "value": &COLOR[32..]}));
    });
    // A Uint is hashed little-endian at its width: 3000000 is 0x2dc6c0.
    let retyped =
        with(
            unshielded(),
            |r| {
                r["args"][1] =
                    json!({"type": "Bytes<16>", "value": "c0c62d00000000000000000000000000"})
            },
        );
    let moved = with(unshielded(), |r| {
        let last = r["args"].as_array_mut().unwrap().pop().unwrap();
        r["witnesses"] = json!([last]);
    });
    let flattened = with(shielded(), |r| {
        let coin = r["witnesses"].as_array_mut().unwrap().remove(0);
        r["args"]
            .as_array_mut()
            .unwrap()
            .extend(coin["fields"].as_array().unwrap().iter().cloned());
    });
    let struct_renamed = with(shielded(), |r| r["witnesses"][0]["type"] = json!("Coin"));
    for (case, request, same_as) in [
        (
            "one Bytes<32> split into two Bytes<16>",
            split,
            unshielded(),
        ),
        ("a Uint<128> written as a Bytes<16>", retyped, unshielded()),
        ("an argument moved to the witnesses", moved, unshielded()),
        (
            "a witness struct flattened into the args",
            flattened,
            shielded(),
        ),
        ("a struct renamed", struct_renamed, shielded()),
    ] {
        assert_eq!(
            contract_challenge(&request),
            contract_challenge(&same_as),
            "{case}"
        );
    }
}

#[test]
fn a_signature_verifies_as_the_circuit_checks_it() {
    let key = JubjubCredential.generate().unwrap();
    let pk = EmbeddedGroupAffine::generator() * be_scalar(key.secret.expose());
    assert_eq!(key.public_key, point_hex(&pk));
    for request in [unshielded(), shielded(), with_point()] {
        let request = request.to_string();
        let signature = JubjubCredential
            .sign(key.secret.expose(), &request)
            .unwrap();
        assert_eq!(signature.len(), 104);
        let big_r =
            EmbeddedGroupAffine::new(be_field(&signature[..32]), be_field(&signature[32..64]))
                .unwrap();
        let s = be_scalar(&signature[64..96]);
        let grind = u64::from_be_bytes(signature[96..].try_into().unwrap());
        let challenge = Request::parse(&request)
            .unwrap()
            .challenge(&big_r, &pk, grind)
            .unwrap();
        // The circuit casts the challenge bytes, read little-endian, to a scalar.
        let c = EmbeddedFr::from_le_bytes(&challenge).expect("challenge ground below r_J");
        assert!(EmbeddedGroupAffine::generator() * s == big_r + pk * c);
        JubjubCredential
            .verify(&key.public_key, &request, &signature)
            .unwrap();
    }
}

#[test]
fn a_tampered_signature_or_request_fails_verify() {
    let key = JubjubCredential.generate().unwrap();
    let request = unshielded().to_string();
    let signature = JubjubCredential
        .sign(key.secret.expose(), &request)
        .unwrap();
    JubjubCredential
        .verify(&key.public_key, &request, &signature)
        .unwrap();

    for (part, index) in [("R", 10), ("s", 70), ("grind nonce", 103)] {
        let mut tampered = signature.clone();
        tampered[index] ^= 1;
        assert!(
            JubjubCredential
                .verify(&key.public_key, &request, &tampered)
                .is_err(),
            "tampered {part}"
        );
    }
    assert!(JubjubCredential
        .verify(&key.public_key, &request, &signature[..103])
        .is_err());

    let edits: [fn(&mut Value); 5] = [
        |r| r["args"][1]["value"] = json!("3000001"),
        |r| r["authNonce"] = json!(4),
        |r| r["account"] = json!(COLOR),
        |r| r["circuit"] = json!("withdraw_shielded"),
        |r| r["scheme"] = json!("midnight:account:auth:v2"),
    ];
    for edit in edits {
        let other = with(unshielded(), edit);
        assert!(
            JubjubCredential
                .verify(&key.public_key, &other.to_string(), &signature)
                .is_err(),
            "{other}"
        );
    }

    let other_key = JubjubCredential.generate().unwrap();
    assert!(JubjubCredential
        .verify(&other_key.public_key, &request, &signature)
        .is_err());
}

#[test]
fn a_small_order_key_never_verifies() {
    // Under the identity, R = s·G satisfies s·G == R + c·pk for every c, so the
    // forged signature below passes the equation and only the small-order check
    // stops it, as the contract's own check does.
    let identity = EmbeddedGroupAffine::identity();
    let request = unshielded().to_string();
    let parsed = Request::parse(&request).unwrap();
    let s = EmbeddedFr::from(1_u64);
    let big_r = EmbeddedGroupAffine::generator() * s;
    let grind = (0..)
        .find(|g| {
            EmbeddedFr::from_le_bytes(&parsed.challenge(&big_r, &identity, *g).unwrap()).is_some()
        })
        .unwrap();
    let mut forged = hex::decode(point_hex(&big_r)).unwrap();
    forged.extend_from_slice(&le(&s.as_le_bytes()));
    forged.extend_from_slice(&u64::to_be_bytes(grind));
    assert!(JubjubCredential
        .verify(&point_hex(&identity), &request, &forged)
        .is_err());
}

#[test]
fn requests_are_parsed_strictly() {
    let cases = [
        (
            "unknown top-level field",
            with(unshielded(), |r| r["version"] = json!(1)),
        ),
        ("missing scheme", without(unshielded(), "scheme")),
        ("missing account", without(unshielded(), "account")),
        ("missing circuit", without(unshielded(), "circuit")),
        ("missing authNonce", without(unshielded(), "authNonce")),
        (
            "args not an array",
            with(unshielded(), |r| r["args"] = json!({})),
        ),
        (
            "a value that is not an object",
            with(unshielded(), |r| r["args"][0] = json!(COLOR)),
        ),
        (
            "a value without a type",
            with(unshielded(), |r| {
                r["args"][0].as_object_mut().unwrap().remove("type");
            }),
        ),
        (
            "a type that is not a string",
            with(unshielded(), |r| r["args"][0]["type"] = json!(32)),
        ),
        (
            "struct fields that are not an array",
            with(shielded(), |r| r["witnesses"][0]["fields"] = json!({})),
        ),
        ("depth > 8", nested(9)),
        (
            "unknown type",
            with(unshielded(), |r| r["args"][1]["type"] = json!("Boolean")),
        ),
        (
            "Uint wider than 128 bits",
            with(unshielded(), |r| r["args"][1]["type"] = json!("Uint<256>")),
        ),
        (
            "Bytes<0>",
            with(unshielded(), |r| {
                r["args"][0] = json!({"type": "Bytes<0>", "value": ""})
            }),
        ),
        (
            "short hex",
            with(unshielded(), |r| r["args"][0]["value"] = json!(&COLOR[2..])),
        ),
        (
            "long hex",
            with(unshielded(), |r| {
                r["args"][2]["value"] = json!(format!("{RECIPIENT}00"))
            }),
        ),
        (
            "null value",
            with(unshielded(), |r| r["args"][0]["value"] = Value::Null),
        ),
        (
            "short account",
            with(unshielded(), |r| r["account"] = json!(&ACCOUNT[2..])),
        ),
        (
            "Uint out of range",
            with(unshielded(), |r| {
                r["args"][1]["value"] = json!("340282366920938463463374607431768211456")
            }),
        ),
        (
            "negative Uint",
            with(unshielded(), |r| r["args"][1]["value"] = json!(-1)),
        ),
        (
            "authNonce out of range",
            with(unshielded(), |r| {
                r["authNonce"] = json!("18446744073709551616")
            }),
        ),
        (
            "not a curve point",
            with(with_point(), |r| {
                r["args"][0]["value"] = json!(format!("{PK_X}{SIG_R_Y}"))
            }),
        ),
    ];
    for (case, request) in cases {
        assert!(
            JubjubCredential.describe(&request.to_string()).is_err(),
            "{case} was accepted"
        );
    }
    for request in [nested(8), unshielded(), shielded(), with_point()] {
        JubjubCredential.describe(&request.to_string()).unwrap();
    }
    let empty = with(unshielded(), |r| r["args"] = json!([]));
    JubjubCredential.describe(&empty.to_string()).unwrap();
}

#[test]
fn a_value_is_a_primitive_or_a_struct() {
    for (case, request, reason) in [
        (
            "missing args",
            without(unshielded(), "args"),
            "missing field `args`",
        ),
        (
            "missing witnesses",
            without(unshielded(), "witnesses"),
            "missing field `witnesses`",
        ),
        (
            "a primitive with fields too",
            with(unshielded(), |r| r["args"][0]["fields"] = json!([])),
            "args[0] has both `value` and `fields`",
        ),
        (
            "a struct with a value too",
            with(shielded(), |r| r["witnesses"][0]["value"] = json!(COLOR)),
            "witnesses[0] has both `value` and `fields`",
        ),
        (
            "neither value nor fields",
            with(unshielded(), |r| {
                r["args"][1].as_object_mut().unwrap().remove("value");
            }),
            "args[1] has neither `value` nor `fields`",
        ),
        (
            "a struct named like a primitive",
            with(shielded(), |r| {
                r["witnesses"][0]["type"] = json!("ZswapCoinPublicKey")
            }),
            "`ZswapCoinPublicKey` is a primitive type",
        ),
        (
            "a struct named like a sized primitive",
            with(shielded(), |r| {
                r["witnesses"][0]["type"] = json!("Bytes<32>")
            }),
            "`Bytes<32>` is a primitive type",
        ),
        (
            "a struct named after no identifier",
            with(shielded(), |r| {
                r["witnesses"][0]["type"] = json!("coin:QualifiedShieldedCoinInfo")
            }),
            "is not a Compact identifier",
        ),
        (
            "a NUL-padded struct name",
            with(shielded(), |r| {
                r["witnesses"][0]["type"] = json!("QualifiedShieldedCoinInfo\0")
            }),
            "is not a Compact identifier",
        ),
        (
            "an unknown key in a value",
            with(unshielded(), |r| r["args"][0]["name"] = json!("color")),
            "args[0].name is not allowed",
        ),
        (
            "an unknown key in a struct field",
            with(shielded(), |r| {
                r["witnesses"][0]["fields"][3]["name"] = json!("mt_index")
            }),
            "witnesses[0].fields[3].name is not allowed",
        ),
        (
            "a primitive written as a struct type",
            with(shielded(), |r| r["args"][1]["type"] = json!("Color")),
            "args[1]: unsupported type `Color`",
        ),
    ] {
        let refusal = JubjubCredential
            .describe(&request.to_string())
            .unwrap_err()
            .to_string();
        assert!(refusal.contains(reason), "{case}: {refusal}");
    }
}

#[test]
fn a_repeated_key_is_refused_anywhere() {
    let unshielded = unshielded().to_string();
    let shielded = shielded().to_string();
    let repeat = |request: &str, pair: &str, before: &str| {
        assert_eq!(request.matches(pair).count(), 1, "{pair}");
        request.replacen(pair, &format!("{before},{pair}"), 1)
    };
    for (case, request) in [
        (
            "request field",
            repeat(&unshielded, r#""authNonce":"3""#, r#""authNonce":"4""#),
        ),
        (
            "value",
            repeat(&unshielded, r#""value":"3000000""#, r#""value":"1""#),
        ),
        (
            "type",
            repeat(&unshielded, r#""type":"Uint<128>""#, r#""type":"Uint<8>""#),
        ),
        (
            "nested struct field",
            repeat(&shielded, r#""value":"66636""#, r#""value":"1""#),
        ),
    ] {
        let refusal = JubjubCredential.describe(&request).unwrap_err().to_string();
        assert!(refusal.contains("appears twice"), "{case}: {refusal}");
    }
}

#[test]
fn a_new_key_is_to_be_enrolled_first() {
    assert!(JubjubCredential
        .create_hint()
        .is_some_and(|h| h.contains("add_device_with_jubjub")));
}

#[test]
fn deleting_warns_that_the_device_stays_enrolled() {
    assert!(JubjubCredential
        .delete_warning()
        .is_some_and(|w| w.contains("enrolled")));
}

#[test]
fn a_circuit_tag_names_one_circuit() {
    // The tag is zero-padded and joined with `:`, so these spellings of
    // withdraw_unshielded would share its DST and challenge while describe
    // reported another circuit.
    assert_eq!(
        dst("midnight:account:auth:v1:withdraw_unshielded").unwrap(),
        dst("midnight:account:auth:v1:withdraw_unshielded\0").unwrap()
    );
    let circuit = |name: &str| {
        let name = name.to_string();
        with(unshielded(), move |r| r["circuit"] = json!(name))
    };
    for (case, request, reason) in [
        (
            "scheme and circuit split at another colon",
            with(circuit("v1:withdraw_unshielded"), |r| {
                r["scheme"] = json!("midnight:account:auth")
            }),
            "only device authorisations",
        ),
        (
            "NUL-padded circuit",
            circuit("withdraw_unshielded\0"),
            "identifier",
        ),
        (
            "colon in circuit",
            circuit("auth:withdraw_unshielded"),
            "identifier",
        ),
        (
            "circuit starting with a digit",
            circuit("1withdraw_unshielded"),
            "identifier",
        ),
        ("empty circuit", circuit(""), "identifier"),
        (
            "tag longer than 64 bytes",
            circuit(&"a".repeat(40)),
            "longer than 64 bytes",
        ),
    ] {
        let refusal = JubjubCredential
            .describe(&request.to_string())
            .unwrap_err()
            .to_string();
        assert!(refusal.contains(reason), "{case}: {refusal}");
    }
    JubjubCredential
        .describe(&circuit(&"a".repeat(39)).to_string())
        .unwrap();
}

#[test]
fn only_device_authorisations_are_signed() {
    let key = JubjubCredential
        .import(&secret(0x0123_4567_89ab_cdef))
        .unwrap();
    let signature = JubjubCredential
        .sign(key.secret.expose(), &unshielded().to_string())
        .unwrap();
    for name in [
        "midnight:account:grant:v1",
        "midnight:account:grant:auth:v1",
        "midnight:account:auth:v2",
        "",
    ] {
        let request = with(unshielded(), |r| r["scheme"] = json!(name)).to_string();
        for (step, refusal) in [
            ("parse", Request::parse(&request).err()),
            ("describe", JubjubCredential.describe(&request).err()),
            (
                "sign",
                JubjubCredential.sign(key.secret.expose(), &request).err(),
            ),
            (
                "verify",
                JubjubCredential
                    .verify(&key.public_key, &request, &signature)
                    .err(),
            ),
        ] {
            let refusal = refusal
                .unwrap_or_else(|| panic!("{step} accepted scheme {name:?}"))
                .to_string();
            assert!(
                refusal.contains("only device authorisations"),
                "{step} {name:?}: {refusal}"
            );
        }
    }
}

#[test]
fn generated_key_is_in_range_and_pk_matches() {
    let r_j = hex::decode(R_J).unwrap();
    for _ in 0..32 {
        let key = JubjubCredential.generate().unwrap();
        let sk = key.secret.expose();
        assert_eq!(sk.len(), 32);
        assert!(sk.iter().any(|b| *b != 0) && sk < r_j.as_slice());
        let pk = EmbeddedGroupAffine::generator() * be_scalar(sk);
        assert_eq!(key.public_key, point_hex(&pk));
        assert_eq!(
            JubjubCredential.import(sk).unwrap().public_key,
            key.public_key
        );
    }
}

#[test]
fn import_rejects_zero_r_j_and_wrong_length() {
    let r_j = hex::decode(R_J).unwrap();
    for (case, secret) in [
        ("zero", vec![0u8; 32]),
        ("r_J", r_j.clone()),
        ("above r_J", vec![0xff; 32]),
        ("31 bytes", vec![1u8; 31]),
        ("33 bytes", vec![1u8; 33]),
    ] {
        assert!(
            matches!(
                JubjubCredential.import(&secret),
                Err(SignerError::InvalidPrivateKey(_))
            ),
            "{case} was accepted"
        );
        assert!(JubjubCredential
            .sign(&secret, &unshielded().to_string())
            .is_err());
    }
    let mut below_r_j = r_j;
    below_r_j[31] -= 1;
    for edge in [secret(1).to_vec(), below_r_j] {
        JubjubCredential.import(&edge).unwrap();
    }
}

#[test]
fn one_request_signed_twice_uses_two_nonces() {
    let key = JubjubCredential
        .import(&secret(0x0123_4567_89ab_cdef))
        .unwrap();
    let request = unshielded().to_string();
    let first = JubjubCredential
        .sign(key.secret.expose(), &request)
        .unwrap();
    let second = JubjubCredential
        .sign(key.secret.expose(), &request)
        .unwrap();
    assert_ne!(first[..64], second[..64], "R repeated");
    for signature in [first, second] {
        JubjubCredential
            .verify(&key.public_key, &request, &signature)
            .unwrap();
    }
}

#[test]
fn describe_reports_account_circuit_and_scheme() {
    let request = with(unshielded(), |r| {
        r["account"] = json!(format!("0x{}", ACCOUNT.to_uppercase()))
    })
    .to_string();
    let context = JubjubCredential.describe(&request).unwrap();
    assert_eq!(context.verifying_contract.as_deref(), Some(ACCOUNT));
    assert_eq!(context.primary_type, "withdraw_unshielded");
    assert_eq!(
        context.domain_name.as_deref(),
        Some("midnight:account:auth:v1")
    );
    assert_eq!(context.domain_chain_id, None);
    assert_eq!(context.domain_version, None);
    assert_eq!(context.raw_json, request);
}

#[test]
fn signature_fields_are_the_circuits_authorising_material() {
    let key = JubjubCredential
        .import(&secret(0x0123_4567_89ab_cdef))
        .unwrap();
    let signature = hex::decode(SIGNATURES[0]).unwrap();
    let fields = JubjubCredential
        .signature_fields(&key.public_key, &signature)
        .unwrap();
    assert_eq!(
        Value::Object(fields),
        json!({
            "scheme": "midnight:account:auth:v1",
            "pk": format!("{PK_X}{PK_Y}"),
            "sigR": &SIGNATURES[0][..128],
            "sigS": &SIGNATURES[0][128..192],
            "grindNonce": 1
        })
    );
    assert!(JubjubCredential
        .signature_fields(&key.public_key, &signature[..103])
        .is_err());
    assert!(JubjubCredential.signature_fields(PK_X, &signature).is_err());
}
