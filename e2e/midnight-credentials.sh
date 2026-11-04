#!/usr/bin/env bash
#
# Offline smoke test for account device keys (`ows credential`) on Midnight. No node, no proof
# server, no funds: every command is local, and the whole run happens in a THROWAWAY vault, so your
# real ~/.ows is never touched (the CLI takes its vault from $HOME, and this script points HOME at a
# fresh temp directory that it deletes on exit).
#
# Checks:
#   • `credential create` refuses an empty passphrase, prints a 128-hex public key under a real one
#     and the reminder to enrol it, and `list` shows origin `generated`;
#   • `credential import` records origin `imported`, and the public key matches the known vector;
#   • an owner signature is 208 hex characters (104 bytes), and signing without the passphrase fails;
#   • `--json` prints the signature hex and its parts and nothing else: signature (sigR ‖ sigS ‖
#     grindNonce), the scheme, pk (the credential's public key), sigR, sigS and grindNonce;
#   • `sign message`, `sign tx` and `wallet export` with --wallet <credential name> all fail with
#     "wallet not found" (no wallet command can see a credential);
#   • an agent token under an `allowed_typed_data_contracts` policy (allowlist written with `0x` and
#     in upper case, to exercise the normalisation) signs for the listed contract, is denied for
#     another contract, and the audit log records the denial;
#   • a token minted without the credential is refused;
#   • one token minted under the owner passphrase holds a wallet sealed under the empty passphrase
#     (as `wallet create` seals it) and a credential, and signs with both;
#   • `credential delete` warns that the key stays enrolled, and removes the encrypted copy from the
#     token file (<vault>/keys/*.json);
#   • a malformed request (an EIP-712 envelope, no witnesses, a value with both a value and fields,
#     a struct named like a primitive, an unknown key in a value) is refused before the key is
#     decrypted, under a wrong passphrase that a well-formed request trips over.
#
# Usage:  ./midnight-credentials.sh
# Env:    OWS_CLI=/path/to/ows   (default: ows/target/debug/ows, built here if missing)
#         PROFILE=release        (use ows/target/release/ows instead)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$SCRIPT_DIR/../ows"
PROFILE="${PROFILE:-debug}"
OWS_CLI="${OWS_CLI:-$WORKSPACE/target/$PROFILE/ows}"
CHAIN="midnight:preview"

if [ -t 1 ]; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'; GREEN=$'\e[32m'; RED=$'\e[31m'; BLUE=$'\e[34m'
else
  BOLD=; DIM=; RESET=; GREEN=; RED=; BLUE=
fi
say()  { printf '\n%s%s%s\n' "$BOLD$BLUE" "$1" "$RESET"; }
note() { printf '%s%s%s\n' "$DIM" "$1" "$RESET"; }

PASS=0; FAIL=0; TOTAL=0
check() {  # check <label> <command...>: passes when the command exits 0
  local label="$1"; shift
  TOTAL=$((TOTAL+1))
  if "$@"; then printf '%s✓ %s%s\n' "$GREEN" "$label" "$RESET"; PASS=$((PASS+1))
  else printf '%s✗ %s%s\n' "$RED" "$label" "$RESET"; FAIL=$((FAIL+1)); fi
}
has()  { printf '%s' "$1" | grep -qE -- "$2"; }
hasnt() { ! printf '%s' "$1" | grep -qE -- "$2"; }

if [ ! -x "$OWS_CLI" ]; then
  note "building ows ($PROFILE) …"
  if [ "$PROFILE" = release ]; then
    (cd "$WORKSPACE" && cargo build --release -p ows-cli) >/dev/null 2>&1 || { echo "build failed"; exit 1; }
  else
    (cd "$WORKSPACE" && cargo build -p ows-cli) >/dev/null 2>&1 || { echo "build failed"; exit 1; }
  fi
fi

REAL_HOME="${HOME:-}"
HOME="$(mktemp -d)"; export HOME
trap 'rm -rf "$HOME"' EXIT
VAULT="$HOME/.ows"
[ "$HOME" != "$REAL_HOME" ] && [ -n "$HOME" ] || { echo "refusing to run outside a temp vault"; exit 1; }
unset OWS_PASSPHRASE LWS_PASSPHRASE OWS_PRIVATE_KEY OWS_WALLET
# No command may prompt: `run` captures stderr, so on a terminal the prompt would be invisible and
# the script would wait forever. Without a terminal on stdin an unset passphrase reads as empty.
exec </dev/null
# The owner passphrase. Each command that needs it gets it through `owner`.
OWNER_PASS="credential-e2e-owner"
owner() { OWS_PASSPHRASE="$OWNER_PASS" "$OWS_CLI" "$@"; }
note "ows: $OWS_CLI"
note "vault: $VAULT"

ows() { "$OWS_CLI" "$@"; }

# The withdraw_unshielded authorisation request from the signer's own tests; $1 is the account.
CONTRACT="a19612afc371b1a4d2fc2410377da895ff7ca406e74449b75dcc32a2b6df7964"
OTHER="1111111111111111111111111111111111111111111111111111111111111111"
COLOR="5cd36fe5ed159246257b476bb67bc8266290581ef3844fcabd7c134b3f8b03ea"
RECIPIENT="b0c1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9e00"
request() {
  cat <<JSON
{"scheme":"midnight:account:auth:v1","account":"$1","circuit":"withdraw_unshielded",
 "args":[{"type":"Bytes<32>","value":"$COLOR"},{"type":"Uint<128>","value":"3000000"},{"type":"UserAddress","value":"$RECIPIENT"}],
 "witnesses":[],"authNonce":3}
JSON
}
IMPORTED_PK="6d8d5ee89b2ace73f44ee9709edb409e7577141965aa793f5c7a076f1e229c3864a8306fd5adc424dc1d677c9cbf195d630cefe1060fc9b74f2e63394e03672f"

# Run a command on a pseudo-terminal: `wallet export` refuses to run without one. OWS_PASSPHRASE is
# set so the command never stops to prompt; the wallet lookup is what is under test.
on_tty() {
  if [ "$(uname)" = Darwin ]; then OWS_PASSPHRASE=x script -q /dev/null "$@" </dev/null | sed 's/\^D//'
  else OWS_PASSPHRASE=x script -qec "$(printf '%q ' "$@")" /dev/null </dev/null | sed 's/\^D//'; fi
  return "${PIPESTATUS[0]}"
}

# Run an ows command, keeping stdout+stderr in OUT and the exit code in RC.
run() { OUT="$("$@" 2>&1)"; RC=$?; printf '%s\n' "$OUT" | sed 's/^/    /'; }

say "1. create and list"
run ows credential create --name device-key --chain midnight
check "create without a passphrase is refused" test "$RC" -ne 0
check "the refusal says why" has "$OUT" 'needs a passphrase'
run owner credential create --name device-key --chain midnight
check "create exits 0" test "$RC" -eq 0
check "create prints a 128-hex public key" has "$OUT" 'Public key: [0-9a-f]{128}$'
check "create says to enrol the key before signing" has "$OUT" 'Next: Enrol this public key.*before signing'
run ows credential list
check "list shows origin generated" has "$OUT" 'Origin:[[:space:]]+generated'

say "2. import"
# The key behind the public key printed in the signer's test vectors (0x0123456789abcdef).
IMPORT_SK="000000000000000000000000000000000000000000000000""0123456789abcdef"
run env OWS_PRIVATE_KEY="$IMPORT_SK" OWS_PASSPHRASE="$OWNER_PASS" "$OWS_CLI" credential import --name imported-key --chain midnight
check "import exits 0" test "$RC" -eq 0
check "import shows the known public key" has "$OUT" "$IMPORTED_PK"
run ows credential list
check "list shows origin imported" has "$OUT" 'Origin:[[:space:]]+imported'

say "3. owner signature"
run owner credential sign --credential device-key --chain "$CHAIN" --request "$(request "$CONTRACT")"
check "owner signature is 208 hex characters" has "$OUT" '^ *[0-9a-f]{208}$'
FIRST="$OUT"
run owner credential sign --credential device-key --chain "$CHAIN" --request "$(request "$CONTRACT")"
check "the second signature is 208 hex characters too" has "$OUT" '^ *[0-9a-f]{208}$'
check "the same request signed twice differs (hedged nonce)" test "$FIRST" != "$OUT"
run ows credential sign --credential device-key --chain "$CHAIN" --request "$(request "$CONTRACT")"
check "signing without the passphrase is refused" test "$RC" -ne 0
check "and returns no signature" hasnt "$OUT" '^ *[0-9a-f]{208}$'
run owner credential sign --credential imported-key --chain "$CHAIN" --request "$(request "$CONTRACT")" --json
check "--json exits 0" test "$RC" -eq 0
check "--json names the scheme" has "$OUT" '^ *"scheme": "midnight:account:auth:v1",?$'
check "--json pk is the credential's public key" has "$OUT" "^ *\"pk\": \"$IMPORTED_PK\",?\$"
check "--json sigR is x ‖ y, 128 hex" has "$OUT" '^ *"sigR": "[0-9a-f]{128}",?$'
check "--json sigS is 64 hex" has "$OUT" '^ *"sigS": "[0-9a-f]{64}",?$'
check "--json grindNonce is a number" has "$OUT" '^ *"grindNonce": [0-9]+,?$'
check "--json signature is 208 hex" has "$OUT" '^ *"signature": "[0-9a-f]{208}",?$'
field() { printf '%s\n' "$OUT" | sed -nE "s/^ *\"$1\": \"?([0-9a-f]+)\"?,?\$/\1/p"; }
check "--json signature is sigR ‖ sigS ‖ grindNonce" test "$(field signature)" = "$(field sigR)$(field sigS)$(printf '%016x' "$(field grindNonce)")"
check "--json has these six fields and no others" test "$(printf '%s\n' "$OUT" | grep -cE '^ *"[^"]+": ')" -eq 6

say "4. wallet commands cannot find a credential"
run ows sign message --chain "$CHAIN" --wallet device-key --message hi
check "sign message: wallet not found" has "$OUT" "wallet not found: 'device-key'"
run ows sign tx --chain "$CHAIN" --wallet device-key --tx 00
check "sign tx: wallet not found" has "$OUT" "wallet not found: 'device-key'"
run on_tty "$OWS_CLI" wallet export --wallet device-key
check "wallet export: wallet not found" has "$OUT" "wallet not found: 'device-key'"
run ows wallet list
check "wallet list exits 0" test "$RC" -eq 0
check "wallet list does not show the credential or skip a file" hasnt "$OUT" 'device-key|skipping'

say "5. an agent token under a contract allowlist"
# 0x and upper case on purpose: the allowlist must still match the bare lowercase contract.
ALLOW="0x$(printf '%s' "$CONTRACT" | tr 'a-f' 'A-F')"
cat > "$HOME/policy.json" <<JSON
{"id":"only-account","name":"only the account contract","version":1,"created_at":"2026-01-01T00:00:00Z",
 "rules":[{"type":"allowed_typed_data_contracts","contracts":["$ALLOW"]}],"action":"deny"}
JSON
run ows policy create --file "$HOME/policy.json"
check "policy created" test "$RC" -eq 0
run owner key create --name agent --credential device-key --policy only-account
check "token created" has "$OUT" 'ows_key_[0-9a-f]+'
TOKEN="$(printf '%s\n' "$OUT" | grep -oE 'ows_key_[0-9a-f]+' | head -1)"

run env OWS_PASSPHRASE="$TOKEN" "$OWS_CLI" credential sign --credential device-key --chain "$CHAIN" --request "$(request "$CONTRACT")"
check "token signs for the listed contract" has "$OUT" '^ *[0-9a-f]{208}$'
run env OWS_PASSPHRASE="$TOKEN" "$OWS_CLI" credential sign --credential device-key --chain "$CHAIN" --request "$(request "$OTHER")"
check "token is denied for another contract" test "$RC" -ne 0
check "the refusal is a policy denial" has "$OUT" 'policy denied'
check "the denial names the contract" has "$OUT" "$OTHER"
AUDIT="$VAULT/logs/audit.jsonl"
check "the audit log records a denied credential_signed" \
  bash -c 'grep credential_signed "$1" | grep "actor=api_key" | grep -i denied | grep -q "$2"' _ "$AUDIT" "$OTHER"
# actor=api_key: the owner sign in section 3 also logs an allowed line for this contract.
check "the audit log records the token's allowed credential_signed" \
  bash -c 'grep credential_signed "$1" | grep "actor=api_key" | grep -vi denied | grep -q "$2"' _ "$AUDIT" "$CONTRACT"
check "the audit log records the owner's credential_signed" \
  bash -c 'grep credential_signed "$1" | grep "actor=owner" | grep -q "outcome=allowed"' _ "$AUDIT"

say "6. a token without the credential is refused"
run owner key create --name agent-other --credential imported-key --policy only-account
OTHER_TOKEN="$(printf '%s\n' "$OUT" | grep -oE 'ows_key_[0-9a-f]+' | head -1)"
run env OWS_PASSPHRASE="$OTHER_TOKEN" "$OWS_CLI" credential sign --credential device-key --chain "$CHAIN" --request "$(request "$CONTRACT")"
check "the second token was minted" test -n "$OTHER_TOKEN"
check "token for another credential is refused" has "$OUT" 'does not have access to credential'
check "and returns no signature" hasnt "$OUT" '^ *[0-9a-f]{208}$'

say "7. one token for a wallet and a credential"
run ows wallet create --name pay
check "wallet created" test "$RC" -eq 0
run owner key create --name agent-both --wallet pay --credential device-key --policy only-account
check "one token minted for the wallet and the credential" has "$OUT" 'ows_key_[0-9a-f]+'
BOTH_TOKEN="$(printf '%s\n' "$OUT" | grep -oE 'ows_key_[0-9a-f]+' | head -1)"
run env OWS_PASSPHRASE="$BOTH_TOKEN" "$OWS_CLI" sign message --chain ethereum --wallet pay --message hi
check "it signs a message with the wallet" has "$OUT" '^ *[0-9a-f]{130}$'
run env OWS_PASSPHRASE="$BOTH_TOKEN" "$OWS_CLI" credential sign --credential device-key --chain "$CHAIN" --request "$(request "$CONTRACT")"
check "it signs with the credential" has "$OUT" '^ *[0-9a-f]{208}$'

say "8. delete removes the copy from the token file"
DEVICE_ID="$(ows credential list | awk '/^ID:/{id=$2} /^Name:[[:space:]]+device-key$/{print id}')"
check "found the credential id" test -n "$DEVICE_ID"
check "the token file holds the credential before delete" \
  bash -c 'grep -l "$1" "$2"/keys/*.json >/dev/null' _ "$DEVICE_ID" "$VAULT"
run ows credential delete --credential device-key --confirm
check "delete exits 0" test "$RC" -eq 0
check "delete warns that the key stays enrolled" has "$OUT" 'stays enrolled'
check "all three token files are still there" test "$(ls "$VAULT"/keys/*.json | wc -l)" -eq 3
check "no token file mentions the credential id after delete" \
  bash -c '! grep -q "$1" "$2"/keys/*.json' _ "$DEVICE_ID" "$VAULT"
check "the credential file is gone" test ! -e "$VAULT/credentials/$DEVICE_ID.json"
run env OWS_PASSPHRASE="$TOKEN" "$OWS_CLI" credential sign --credential device-key --chain "$CHAIN" --request "$(request "$CONTRACT")"
check "the old token can no longer sign: credential not found" has "$OUT" 'credential not found'
check "and returns no signature after delete" hasnt "$OUT" '^ *[0-9a-f]{208}$'

say "9. malformed requests are refused before the key is decrypted"
# A wrong passphrase: a request that got past the checks would fail at decryption instead.
refused() {  # refused <label> <pattern> <request>: the refusal matches and no signature comes back
  run env OWS_PASSPHRASE=not-the-passphrase "$OWS_CLI" credential sign --credential imported-key --chain "$CHAIN" --request "$3"
  check "$1" bash -c '[ "$1" -ne 0 ] && printf "%s" "$2" | grep -qE -- "$3" && ! printf "%s" "$2" | grep -qE "decryption failed|[0-9a-f]{208}"' _ "$RC" "$OUT" "$2"
}
run env OWS_PASSPHRASE=not-the-passphrase "$OWS_CLI" credential sign --credential imported-key --chain "$CHAIN" --request "$(request "$CONTRACT")"
check "a well-formed request under the wrong passphrase fails at decryption" has "$OUT" 'decryption failed'
refused "an EIP-712 envelope is refused" 'unknown field `types`' \
  '{"types":{"withdraw_unshielded":[{"name":"color","type":"Bytes<32>"}]},"primaryType":"withdraw_unshielded","domain":{"name":"midnight:account:auth:v1","verifyingContract":"'"$CONTRACT"'","authNonce":3},"message":{"color":"'"$COLOR"'"}}'
refused "a request without witnesses is refused" 'missing field `witnesses`' \
  '{"scheme":"midnight:account:auth:v1","account":"'"$CONTRACT"'","circuit":"withdraw_unshielded","args":[],"authNonce":3}'
refused "a value with both a value and fields is refused" 'args\[0\] has both `value` and `fields`' \
  '{"scheme":"midnight:account:auth:v1","account":"'"$CONTRACT"'","circuit":"withdraw_unshielded","args":[{"type":"Bytes<32>","value":"'"$COLOR"'","fields":[]}],"witnesses":[],"authNonce":3}'
refused "a struct named like a primitive is refused" '`UserAddress` is a primitive type' \
  '{"scheme":"midnight:account:auth:v1","account":"'"$CONTRACT"'","circuit":"withdraw_shielded","args":[],"witnesses":[{"type":"UserAddress","fields":[{"type":"Bytes<32>","value":"'"$COLOR"'"}]}],"authNonce":3}'
refused "an unknown key in a value is refused" 'args\[0\]\.name is not allowed' \
  '{"scheme":"midnight:account:auth:v1","account":"'"$CONTRACT"'","circuit":"withdraw_unshielded","args":[{"name":"color","type":"Bytes<32>","value":"'"$COLOR"'"}],"witnesses":[],"authNonce":3}'

echo
if [ "$FAIL" -eq 0 ]; then printf '%s%d/%d checks passed%s\n' "$GREEN" "$PASS" "$TOTAL" "$RESET"
else printf '%s%d/%d checks passed, %d failed%s\n' "$RED" "$PASS" "$TOTAL" "$FAIL" "$RESET"; fi
[ "$FAIL" -eq 0 ]
