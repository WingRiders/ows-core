"""Tests for ows Python bindings."""

import copy
import json
import tempfile
import pytest
import ows


@pytest.fixture
def vault_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_generate_mnemonic_12():
    phrase = ows.generate_mnemonic(12)
    assert len(phrase.split()) == 12


def test_generate_mnemonic_24():
    phrase = ows.generate_mnemonic(24)
    assert len(phrase.split()) == 24


def test_derive_address_evm():
    phrase = ows.generate_mnemonic(12)
    # "evm" still works via backward compat
    address = ows.derive_address(phrase, "evm")
    assert address.startswith("0x")
    assert len(address) == 42


def test_derive_address_ethereum():
    phrase = ows.generate_mnemonic(12)
    address = ows.derive_address(phrase, "ethereum")
    assert address.startswith("0x")
    assert len(address) == 42


def test_derive_address_all_supported_chains():
    phrase = ows.generate_mnemonic(12)
    for chain in ["evm", "solana", "sui", "bitcoin", "cosmos", "tron", "ton", "filecoin", "xrpl", "nano", "near", "cardano"]:
        address = ows.derive_address(phrase, chain)
        assert len(address) > 0


def test_create_and_list_wallets(vault_dir):
    wallet = ows.create_wallet("test-wallet", vault_path_opt=vault_dir)
    assert wallet["name"] == "test-wallet"
    assert isinstance(wallet["accounts"], list)
    assert len(wallet["accounts"]) == 16

    # Verify each chain family is present
    chain_ids = [a["chain_id"] for a in wallet["accounts"]]
    assert any(c.startswith("eip155:") for c in chain_ids)
    assert any(c.startswith("solana:") for c in chain_ids)
    assert any(c.startswith("sui:") for c in chain_ids)
    assert any(c.startswith("bip122:") for c in chain_ids)
    assert any(c.startswith("cosmos:") for c in chain_ids)
    assert any(c.startswith("tron:") for c in chain_ids)
    assert any(c.startswith("ton:") for c in chain_ids)
    assert any(c.startswith("spark:") for c in chain_ids)
    assert any(c.startswith("fil:") for c in chain_ids)
    assert any(c.startswith("xrpl:") for c in chain_ids)
    assert any(c.startswith("nano:") for c in chain_ids)
    assert any(c.startswith("near:") for c in chain_ids)
    assert any(c.startswith("cip34:") for c in chain_ids)

    wallets = ows.list_wallets(vault_path_opt=vault_dir)
    assert len(wallets) == 1
    assert wallets[0]["id"] == wallet["id"]


def test_get_wallet(vault_dir):
    wallet = ows.create_wallet("lookup", vault_path_opt=vault_dir)

    found = ows.get_wallet("lookup", vault_path_opt=vault_dir)
    assert found["id"] == wallet["id"]

    found = ows.get_wallet(wallet["id"], vault_path_opt=vault_dir)
    assert found["name"] == "lookup"


def test_rename_wallet(vault_dir):
    ows.create_wallet("old-name", vault_path_opt=vault_dir)
    ows.rename_wallet("old-name", "new-name", vault_path_opt=vault_dir)

    found = ows.get_wallet("new-name", vault_path_opt=vault_dir)
    assert found["name"] == "new-name"


def test_export_wallet(vault_dir):
    ows.create_wallet("exportable", vault_path_opt=vault_dir)
    secret = ows.export_wallet("exportable", vault_path_opt=vault_dir)
    assert len(secret.split()) == 12


def test_delete_wallet(vault_dir):
    wallet = ows.create_wallet("deletable", vault_path_opt=vault_dir)
    ows.delete_wallet("deletable", vault_path_opt=vault_dir)

    wallets = ows.list_wallets(vault_path_opt=vault_dir)
    assert len(wallets) == 0


def test_import_wallet_mnemonic(vault_dir):
    phrase = ows.generate_mnemonic(12)
    expected_addr = ows.derive_address(phrase, "ethereum")

    wallet = ows.import_wallet_mnemonic(
        "imported", phrase, vault_path_opt=vault_dir
    )
    assert wallet["name"] == "imported"
    assert len(wallet["accounts"]) == 16

    # EVM account should match derived address
    evm_account = next(a for a in wallet["accounts"] if a["chain_id"].startswith("eip155:"))
    assert evm_account["address"] == expected_addr


def test_sign_transaction(vault_dir):
    ows.create_wallet("signer", vault_path_opt=vault_dir)

    tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    result = ows.sign_transaction(
        "signer", "evm", tx_hex, vault_path_opt=vault_dir
    )
    assert len(result["signature"]) > 0
    assert result["recovery_id"] is not None


def test_sign_message(vault_dir):
    ows.create_wallet("msg-signer", vault_path_opt=vault_dir)

    result = ows.sign_message(
        "msg-signer", "evm", "hello world", vault_path_opt=vault_dir
    )
    assert len(result["signature"]) > 0


def test_sign_hash_and_authorization_owner_mode(vault_dir):
    wallet = ows.create_wallet("hash-owner", vault_path_opt=vault_dir)

    hash_result = ows.sign_hash(
        wallet["id"], "base", "11" * 32, vault_path_opt=vault_dir
    )
    assert len(hash_result["signature"]) > 0
    assert hash_result["recovery_id"] in (0, 1)

    auth_result = ows.sign_authorization(
        wallet["id"],
        "base",
        "0x1111111111111111111111111111111111111111",
        "7",
        vault_path_opt=vault_dir,
    )
    assert len(auth_result["signature"]) > 0
    assert auth_result["recovery_id"] in (0, 1)


def test_sign_hash_and_authorization_api_key_mode(vault_dir):
    wallet = ows.create_wallet("hash-agent", vault_path_opt=vault_dir)

    ows.create_policy(
        """{
          "id": "base-only-hash",
          "name": "Base Only Hash",
          "version": 1,
          "created_at": "2026-03-22T00:00:00Z",
          "rules": [
            {"type": "allowed_chains", "chain_ids": ["eip155:8453"]}
          ],
          "action": "deny"
        }""",
        vault_path_opt=vault_dir,
    )

    key = ows.create_api_key(
        "hash-agent-key",
        [wallet["id"]],
        ["base-only-hash"],
        "",
        vault_path_opt=vault_dir,
    )

    hash_result = ows.sign_hash(
        wallet["id"], "base", "22" * 32, key["token"], vault_path_opt=vault_dir
    )
    assert len(hash_result["signature"]) > 0

    auth_result = ows.sign_authorization(
        wallet["id"],
        "base",
        "0x1111111111111111111111111111111111111111",
        "7",
        key["token"],
        vault_path_opt=vault_dir,
    )
    assert len(auth_result["signature"]) > 0

    with pytest.raises(RuntimeError, match="not in allowlist"):
        ows.sign_authorization(
            wallet["id"],
            "ethereum",
            "0x1111111111111111111111111111111111111111",
            "7",
            key["token"],
            vault_path_opt=vault_dir,
        )


def test_sign_typed_data_with_api_key(vault_dir):
    wallet = ows.create_wallet("td-api-test", vault_path_opt=vault_dir)

    # Register a policy allowing Base chains
    ows.create_policy(json.dumps({
        "id": "td-base-only",
        "name": "Base Only",
        "version": 1,
        "created_at": "2026-03-22T00:00:00Z",
        "rules": [
            {"type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"]},
        ],
        "action": "deny",
    }), vault_path_opt=vault_dir)

    # Create API key bound to the wallet and policy
    key = ows.create_api_key(
        "td-agent", [wallet["id"]], ["td-base-only"], "",
        vault_path_opt=vault_dir,
    )
    assert key["token"].startswith("ows_key_")

    # EIP-712 typed data (the standard "Mail" example)
    typed_data_json = json.dumps({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"},
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"},
            ],
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 8453,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!",
        },
    })

    # Sign on allowed chain -- should succeed
    result = ows.sign_typed_data(
        wallet["id"], "base", typed_data_json,
        passphrase=key["token"], vault_path_opt=vault_dir,
    )
    assert len(result["signature"]) > 0
    assert result["recovery_id"] is not None

    # Sign on denied chain -- should fail
    # Build typed data with chainId=1 matching ethereum so the domain check passes
    # and AllowedChains (base-only) correctly denies
    eth_td = copy.deepcopy(json.loads(typed_data_json))
    eth_td["domain"]["chainId"] = 1
    eth_typed_data_json = json.dumps(eth_td)
    with pytest.raises(Exception, match="not in allowlist"):
        ows.sign_typed_data(
            wallet["id"], "ethereum", eth_typed_data_json,
            passphrase=key["token"], vault_path_opt=vault_dir,
        )

    # Cleanup
    ows.revoke_api_key(key["id"], vault_path_opt=vault_dir)
    ows.delete_policy("td-base-only", vault_path_opt=vault_dir)
    ows.delete_wallet(wallet["id"], vault_path_opt=vault_dir)


def test_sign_typed_data_respects_allowed_typed_data_contracts(vault_dir):
    wallet = ows.create_wallet("td-contract-test", vault_path_opt=vault_dir)

    ows.create_policy(json.dumps({
        "id": "td-contract-only",
        "name": "Typed Data Contract Only",
        "version": 1,
        "created_at": "2026-03-22T00:00:00Z",
        "rules": [
            {"type": "allowed_chains", "chain_ids": ["eip155:8453"]},
            {
                "type": "allowed_typed_data_contracts",
                "contracts": ["0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"],
            },
        ],
        "action": "deny",
    }), vault_path_opt=vault_dir)

    key = ows.create_api_key(
        "td-contract-agent",
        [wallet["id"]],
        ["td-contract-only"],
        "",
        vault_path_opt=vault_dir,
    )

    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Mail": [{"name": "contents", "type": "string"}],
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 8453,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        },
        "message": {
            "contents": "Hello, Bob!",
        },
    }

    allowed = ows.sign_typed_data(
        wallet["id"],
        "base",
        json.dumps(typed_data),
        passphrase=key["token"],
        vault_path_opt=vault_dir,
    )
    assert len(allowed["signature"]) > 0

    denied_typed_data = copy.deepcopy(typed_data)
    denied_typed_data["domain"]["verifyingContract"] = "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC"

    with pytest.raises(Exception, match="not in allowed list"):
        ows.sign_typed_data(
            wallet["id"],
            "base",
            json.dumps(denied_typed_data),
            passphrase=key["token"],
            vault_path_opt=vault_dir,
        )

    ows.revoke_api_key(key["id"], vault_path_opt=vault_dir)
    ows.delete_policy("td-contract-only", vault_path_opt=vault_dir)
    ows.delete_wallet(wallet["id"], vault_path_opt=vault_dir)


ACCOUNT = "a19612afc371b1a4d2fc2410377da895ff7ca406e74449b75dcc32a2b6df7964"
COLOR = "5cd36fe5ed159246257b476bb67bc8266290581ef3844fcabd7c134b3f8b03ea"
RECIPIENT = "b0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9e00"


def withdraw_unshielded():
    return json.dumps({
        "scheme": "midnight:account:auth:v1",
        "account": ACCOUNT,
        "circuit": "withdraw_unshielded",
        "args": [
            {"type": "Bytes<32>", "value": COLOR},
            {"type": "Uint<128>", "value": "3000000"},
            {"type": "UserAddress", "value": "0x" + RECIPIENT},
        ],
        "witnesses": [],
        "authNonce": "3",
    })


def test_credential_create_list_sign_delete(vault_dir):
    cred = ows.create_credential("passport-device", "midnight", passphrase="pw", vault_path_opt=vault_dir)
    assert cred["name"] == "passport-device"
    assert cred["chain"] == "midnight"
    assert cred["origin"] == "generated"
    assert len(cred["public_key"]) == 128
    assert not any("secret" in k or "crypto" in k for k in cred)

    listed = ows.list_credentials(vault_path_opt=vault_dir)
    assert [c["public_key"] for c in listed] == [cred["public_key"]]
    assert ows.get_credential("passport-device", vault_path_opt=vault_dir)["id"] == cred["id"]

    sig = ows.sign_with_credential(
        "passport-device", "midnight", withdraw_unshielded(), passphrase="pw", vault_path_opt=vault_dir
    )
    assert sorted(sig) == ["grindNonce", "pk", "scheme", "sigR", "sigS", "signature"]
    assert sig["scheme"] == "midnight:account:auth:v1"
    assert sig["pk"] == cred["public_key"]
    assert len(sig["sigR"]) == 128 and int(sig["sigR"], 16) >= 0
    assert len(sig["sigS"]) == 64 and int(sig["sigS"], 16) >= 0
    assert isinstance(sig["grindNonce"], int)
    assert sig["signature"] == sig["sigR"] + sig["sigS"] + format(sig["grindNonce"], "016x")

    ows.delete_credential(cred["id"], vault_path_opt=vault_dir)
    assert ows.list_credentials(vault_path_opt=vault_dir) == []


def test_credential_import_is_marked_imported(vault_dir):
    cred = ows.import_credential("imported", "midnight", "00" * 31 + "7b", passphrase="pw", vault_path_opt=vault_dir)
    assert cred["origin"] == "imported"
    assert len(cred["public_key"]) == 128


def test_credential_wrong_chain_is_refused(vault_dir):
    ows.create_credential("c", "midnight", passphrase="pw", vault_path_opt=vault_dir)
    with pytest.raises(Exception):
        ows.sign_with_credential("c", "evm", withdraw_unshielded(), passphrase="pw", vault_path_opt=vault_dir)


def test_api_key_with_credential_ids(vault_dir):
    wallet = ows.create_wallet("w", passphrase="pw", vault_path_opt=vault_dir)
    cred = ows.create_credential("c", "midnight", passphrase="pw", vault_path_opt=vault_dir)
    plain = ows.create_api_key("plain", [wallet["id"]], [], "pw", vault_path_opt=vault_dir)
    assert plain["token"].startswith("ows_key_")
    key = ows.create_api_key(
        "with-cred", [wallet["id"]], [], "pw", vault_path_opt=vault_dir, credential_ids=[cred["id"]]
    )
    sig = ows.sign_with_credential(
        "c", "midnight", withdraw_unshielded(), passphrase=key["token"], vault_path_opt=vault_dir
    )
    assert sig["pk"] == cred["public_key"]
    assert len(sig["sigR"]) == 128


def test_list_api_keys_hides_credential_secrets(vault_dir):
    wallet = ows.create_wallet("w", passphrase="pw", vault_path_opt=vault_dir)
    cred = ows.create_credential("c", "midnight", passphrase="pw", vault_path_opt=vault_dir)
    ows.create_api_key(
        "with-cred", [wallet["id"]], [], "pw", vault_path_opt=vault_dir, credential_ids=[cred["id"]]
    )
    [listed] = ows.list_api_keys(vault_path_opt=vault_dir)
    assert listed["credential_ids"] == [cred["id"]]
    assert "wallet_secrets" not in listed
    assert "credential_secrets" not in listed


def test_credential_audit_records_match_the_cli(vault_dir):
    cred = ows.create_credential("c", "midnight", passphrase="pw", vault_path_opt=vault_dir)
    ows.sign_with_credential(
        "c", "midnight:preview", withdraw_unshielded(), passphrase="pw", vault_path_opt=vault_dir
    )
    key = ows.create_api_key("agent", [], [], "pw", vault_path_opt=vault_dir, credential_ids=[cred["id"]])
    ows.revoke_api_key(key["id"], vault_path_opt=vault_dir)
    ows.delete_credential("c", vault_path_opt=vault_dir)
    with open(f"{vault_dir}/logs/audit.jsonl") as f:
        log = [json.loads(line) for line in f]
    assert [r["operation"] for r in log] == [
        "credential_created",
        "credential_signed",
        "create_api_key",
        "revoke_api_key",
        "credential_deleted",
    ]
    assert log[1]["chain_id"] == "midnight:preview"
    assert log[1]["details"].startswith(f"credential_id={cred['id']}, ")
    assert log[1]["details"].endswith("actor=owner, outcome=allowed")
    assert not any("wallet_id" in r for r in log)


def test_a_secret_in_the_scheme_slot_is_not_echoed(vault_dir):
    secret = "0123456789abcdef0123456789abcdef"
    with pytest.raises(Exception) as created:
        ows.create_credential("c", "midnight", secret, "pw", vault_dir)
    assert secret not in str(created.value)
    with pytest.raises(Exception) as imported:
        ows.import_credential("c", "midnight", "jubjub", secret, "pw", vault_dir)
    assert secret not in str(imported.value)
