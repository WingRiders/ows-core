#!/usr/bin/env bash
#
# End-to-end run of OWS funding proven contract-call transactions on a live ledger-9 network
# (stagenet by default). A small dapp harness (e2e/contract-calls/) compiles six test contracts,
# deploys them through OWS once, and for each case builds and proves an UNBALANCED call
# transaction plus the disclosure of every call in it — the `balanceUnsealedTransaction` request a
# dapp hands the wallet. Then:
#
#   A. Funding. Each call shape is balanced, paid for and submitted by OWS, and lands:
#        single         Single.record(amount, tag)                      one call, no value
#        composed       Caller.write_then_read(x) → Tally.set, Tally.get   a three-call tree
#        value          Payer.pay_from_wallet(NIGHT, 1) → Till.take_unshielded   the wallet pays a tree
#        value-forward  Payer.forward_from_wallet(NIGHT, 1) → Till.take_unshielded  a callee's intake
#        shielded       Vault.deposit_shielded(coin)                     a shielded deposit
#      For `value`, the Till's on-chain balance grows by exactly the amount the wallet paid once.
#
#   B. Policy over contract calls (agent token, executable policy over chain_extra.contracts), all
#      decided at the plan→authorize seam before anything is proved:
#        B1 an allowlisted call whose disclosed argument is under the cap passes; over the cap, with
#           no disclosure, or a call outside the allowlist is denied
#        B2 a call tree is judged whole: one unlisted callee denies it; listing every call passes it
#        B3 a pinned verifier key that does not match the contract's denies it
#        B4 a disclosure that does not open the call is refused before any policy runs
#
#   C. Sponsorship. A transaction that moves none of the wallet's value, asked with payFees:false,
#      comes back sealed and unchanged with no signature from the wallet — then a sponsor pays its
#      fee by merging and it lands.
#
#   D. The mempool wall. A fresh wallet holding only unregistered NIGHT can pay a fee only by a
#      registration, which for a small call puts more guaranteed work in the transaction than its size
#      allows (OutsideTimeToDismiss). OWS refuses it before proving, naming the wall.
#
#   E. DUST spend proofs. N fundings, each started the moment the previous one lands — when its block
#      has just changed the dust trees — none refused with ledger error 170.
#
# Usage:  WALLET=<funded wallet> ./e2e/midnight-contract-calls.sh [network]
# Env:    PASS                owner passphrase of WALLET (default empty, as `ows wallet import` sets it)
#         PROOF_SERVER_URL    a ledger-9 proof server (default http://localhost:6301)
#         SHIELDED_COLOR      a shielded token WALLET holds at least 1000 of (default: stagenet's
#                             playground faucet token)
#         PARTS               which parts to run (default "A B C D E")
#         E_RUNS              fundings in part E (default 10)
#         AUTO=1              no Enter-pauses
# Needs:  bun, compact (compactc 0.34.0), a ledger-9 proof server, and WALLET funded with NIGHT, DUST
#         generation and SHIELDED_COLOR. Parts A, C, D and E spend from WALLET (fees, 1 NIGHT to the
#         Till per value run, 1000 SHIELDED_COLOR to the Vault, 300 NIGHT to part D's fresh wallet).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$SCRIPT_DIR/../ows"
HARNESS="$SCRIPT_DIR/contract-calls"
CHAIN="${1:-${CHAIN:-midnight:stagenet}}"
NETWORK="${CHAIN#midnight:}"
PASS="${PASS:-}"
PARTS="${PARTS:-A B C D E}"
E_RUNS="${E_RUNS:-10}"
AUTO="${AUTO:-}"
export PROOF_SERVER_URL="${PROOF_SERVER_URL:-http://localhost:6301}"
export SHIELDED_COLOR="${SHIELDED_COLOR:-1ff34b30e33b5a3e69037149ba1c787bed7dfd25274594e1ec8b391ff29fac93}"
export NETWORK

if [ -t 1 ]; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'; CYAN=$'\e[36m'; GREEN=$'\e[32m'; RED=$'\e[31m'; BLUE=$'\e[34m'
else
  BOLD=; DIM=; RESET=; CYAN=; GREEN=; RED=; BLUE=
fi
say()  { printf '\n%s%s%s\n' "$BOLD$BLUE" "$1" "$RESET"; }
note() { printf '%s%s%s\n' "$DIM" "$1" "$RESET"; }
PASSED=0; FAILED=0; FAILURES=()
pass() { printf '%s✓ %s%s\n' "$GREEN" "$1" "$RESET"; PASSED=$((PASSED + 1)); }
fail() { printf '%s✗ %s%s\n' "$RED" "$1" "$RESET"; FAILED=$((FAILED + 1)); FAILURES+=("$1"); }
step() {
  printf '\n%s▶ %s%s\n' "$BOLD$BLUE" "$1" "$RESET"
  printf '%s$ %s%s\n' "$CYAN" "$2" "$RESET"
  if [ -z "$AUTO" ]; then printf '%s   … press Enter to run%s' "$DIM" "$RESET"; read -r _; fi
}
part() { case " $PARTS " in *" $1 "*) return 0;; *) return 1;; esac; }

WALLET="${WALLET:?Set WALLET to a funded OWS wallet.}"
OWS="$WORKSPACE/target/release/ows"
export OWS WALLET

say "OWS contract-call funding e2e on $CHAIN"
note "wallet: $WALLET   proof server: $PROOF_SERVER_URL   parts: $PARTS"

# ── Build OWS from this checkout and the dapp harness ─────────────────────────────────────────
step "build ows (release) from this checkout" "cargo build --release -p ows-cli"
cargo build --release -p ows-cli --manifest-path "$WORKSPACE/Cargo.toml" || exit 1
step "install and compile the dapp harness, deploy what is not live" \
  "(cd e2e/contract-calls && bun install && bun run compile && bun src/cli.ts deploy)"
(cd "$HARNESS" && bun install --frozen-lockfile >/dev/null && bun run compile >/dev/null) || exit 1
(cd "$HARNESS" && OWS_PASSPHRASE="$PASS" bun src/cli.ts deploy) || exit 1

harness() { (cd "$HARNESS" && bun src/cli.ts "$@"); }
address() { harness address "$1"; }

# The line of OUT that says what went wrong: OWS's own error, not the diagnostics after it.
first_error() { printf '%s\n' "$OUT" | grep -m1 -E '^error:' | cut -c1-240; }

# send <label> <credential> <request-json> → sets OUT, HASH; returns the exit code of ows
send() {
  OUT="$(OWS_PASSPHRASE="$2" "$OWS" sign send-tx --wallet "$WALLET" --chain "$CHAIN" --json --tx "$3" 2>&1)"
  local rc=$?
  HASH="$(printf '%s\n' "$OUT" | grep -oE '"tx_hash": *"0x[0-9a-f]+"' | grep -oE '0x[0-9a-f]+' | head -1)"
  return $rc
}
# sign <credential> <request-json> → sets OUT; `ows sign tx`: plan, gate, authorize, seal — no broadcast
sign() {
  OUT="$(OWS_PASSPHRASE="$1" "$OWS" sign tx --wallet "$WALLET" --chain "$CHAIN" --json --tx "$2" 2>&1)"
}
landed() {  # landed <hash> <expected-call-count> <label>
  local result status calls
  result="$(harness wait "$1")"
  status="$(printf '%s' "$result" | python3 -c 'import json,sys; print((json.load(sys.stdin).get("transactionResult") or {}).get("status"))')"
  calls="$(printf '%s' "$result" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["contractActions"]))')"
  if [ "$status" = SUCCESS ] && [ "$calls" = "$2" ]; then pass "$3: landed, $calls call(s), SUCCESS"
  else fail "$3: status=$status calls=$calls (want SUCCESS, $2)"; fi
}
till_night() {
  curl -s -X POST "https://indexer.$NETWORK.shielded.tools/api/v4/graphql" -H 'content-type: application/json' \
    -d "{\"query\":\"{ contractAction(address: \\\"$(address Till)\\\") { unshieldedBalances { tokenType amount } } }\"}" |
    python3 -c 'import json,sys
b=json.load(sys.stdin)["data"]["contractAction"]["unshieldedBalances"]
print(sum(int(x["amount"]) for x in b if int(x["tokenType"],16)==0))'
}

# ═══ A. Funding ════════════════════════════════════════════════════════════════════════════════
if part A; then
  say "A. OWS funds each call shape, and it lands"
  for spec in single:1 composed:3 value:2 value-forward:2 shielded:1; do
    case_name="${spec%%:*}"; calls="${spec##*:}"
    if [ "$case_name" = value ]; then before="$(till_night)"; fi
    step "fund $case_name" "ows sign send-tx --tx \"\$(bun src/cli.ts request $case_name)\""
    if ! req="$(harness request "$case_name")"; then fail "A $case_name: the harness could not build the call"; continue; fi
    if send "A $case_name" "$PASS" "$req" && [ -n "$HASH" ]; then
      landed "$HASH" "$calls" "A $case_name"
    else
      fail "A $case_name: $(first_error)"
    fi
    if [ "$case_name" = value ]; then
      after="$(till_night)"
      if [ "$((after - before))" = 1000000 ]; then pass "A value: the Till holds exactly 1 NIGHT more ($before → $after)"
      else fail "A value: the Till moved by $((after - before)), not 1000000"; fi
    fi
  done
fi

# ═══ B. Policy over contract calls ═════════════════════════════════════════════════════════════
TMP="$(mktemp -d)"
# Every policy part B registers; `policy` runs in a command substitution, so it cannot add to a list.
POLICIES=(ows-e2e-cc-record ows-e2e-cc-tree-partial ows-e2e-cc-tree-whole ows-e2e-cc-pin)
# Revoke every key carrying `name` and delete the policy of that id: an interrupted run leaves both.
forget() {
  local id
  for id in $("$OWS" key list 2>/dev/null | awk -v n="$1" '/^ID:/{id=$2} /^Name:/{ if ($2==n) print id }'); do
    "$OWS" key revoke --id "$id" --confirm >/dev/null 2>&1
  done
  "$OWS" policy delete --id "$1" --confirm >/dev/null 2>&1
}
cleanup() {
  for p in "${POLICIES[@]:-}"; do [ -n "$p" ] && forget "$p"; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# policy <id> <rules-json> → prints an agent token bound to an executable policy enforcing the rules.
# rules: {"<address>.<entry point>": {"verifier_key": "<sha256>"?, "max_first_arg": <n>?}}. A call
# not in the rules, a pinned key that differs, an argument over its cap or missing arguments deny the
# whole transaction. The first, keyless pass carries no chain_extra and is allowed.
policy() {
  local id="$1" rules="$2" prog="$TMP/$1.py"
  cat >"$prog" <<PY
#!/usr/bin/env python3
import json, sys
RULES = json.loads('''$rules''')
ctx = json.load(sys.stdin)
extra = (ctx.get("transaction") or {}).get("chain_extra")
def out(allow, reason): print(json.dumps({"allow": allow, "reason": reason})); sys.exit(0)
if extra is None: out(True, "first pass")
for c in extra.get("contracts", []):
    if c.get("kind") != "call": continue
    name = f"{c['address']}.{c['entry_point']}"
    rule = RULES.get(name)
    if rule is None: out(False, f"call to {c['entry_point']} at {c['address'][:12]}… is not allowed")
    if "verifier_key" in rule and c.get("verifier_key") != rule["verifier_key"]:
        out(False, f"{c['entry_point']}: verifier key {str(c.get('verifier_key'))[:12]}… is not the pinned {rule['verifier_key'][:12]}…")
    if "max_first_arg" in rule:
        args = c.get("arguments")
        if not args: out(False, f"{c['entry_point']}: arguments not disclosed")
        value = int(args["input"][0]["uint"])
        if value > rule["max_first_arg"]: out(False, f"{c['entry_point']}: argument {value} over the cap {rule['max_first_arg']}")
out(True, f"{len(extra.get('contracts', []))} contract record(s) allowed")
PY
  chmod +x "$prog"
  printf '{"id":"%s","name":"%s","version":1,"created_at":"2026-10-28T00:00:00Z","rules":[],"executable":"%s","action":"deny"}' \
    "$id" "$id" "$prog" >"$TMP/$id.json"
  forget "$id"
  "$OWS" policy create --file "$TMP/$id.json" >/dev/null || return 1
  OWS_PASSPHRASE="$PASS" "$OWS" key create --name "$id" --wallet "$WALLET" --policy "$id" 2>&1 |
    grep -oE 'ows_key_[A-Za-z0-9_.-]+' | head -1
}
expect_denied() {  # expect_denied <label> <reason-fragment>
  if printf '%s' "$OUT" | grep -qi 'policy denied' && printf '%s' "$OUT" | grep -qF "$2"; then pass "$1: denied — $2"
  else fail "$1: expected a denial mentioning '$2': $(printf '%s' "$OUT" | tail -2)"; fi
}
expect_signed() {  # expect_signed <label>
  if printf '%s' "$OUT" | grep -q '"transaction"'; then pass "$1: allowed and signed"
  else fail "$1: expected a signed transaction: $(printf '%s' "$OUT" | tail -2)"; fi
}

if part B; then
  say "B. Policy over contract calls, decided at the seam before proving"
  SINGLE="$(address Single)"; CALLER="$(address Caller)"; TALLY="$(address Tally)"
  RECORD_VK="$(shasum -a 256 "$HARNESS/contracts/managed/Single/keys/record.verifier" | cut -d' ' -f1)"
  note "Single.record's verifier key, as compiled: $RECORD_VK"

  T="$(policy ows-e2e-cc-record "{\"$SINGLE.record\": {\"verifier_key\": \"$RECORD_VK\", \"max_first_arg\": 20000}}")"
  step "B1 record(12345), disclosed, cap 20000, key pinned" "OWS_PASSPHRASE=<token> ows sign tx …"
  sign "$T" "$(harness request single --amount 12345)"; expect_signed "B1 under the cap"
  step "B1 record(50000)" "OWS_PASSPHRASE=<token> ows sign tx …"
  sign "$T" "$(harness request single --amount 50000)"; expect_denied "B1 over the cap" "argument 50000 over the cap 20000"
  step "B1 record(12345), arguments not disclosed" "OWS_PASSPHRASE=<token> ows sign tx …"
  sign "$T" "$(harness request single --amount 12345 --disclose none)"; expect_denied "B1 undisclosed" "arguments not disclosed"
  step "B1 a call outside the allowlist (Payer.pay_from_wallet)" "OWS_PASSPHRASE=<token> ows sign tx …"
  sign "$T" "$(harness request value)"; expect_denied "B1 unlisted contract" "pay_from_wallet"

  T="$(policy ows-e2e-cc-tree-partial "{\"$CALLER.write_then_read\": {}, \"$TALLY.set\": {}}")"
  step "B2 the tree with Tally.get unlisted" "OWS_PASSPHRASE=<token> ows sign tx …"
  sign "$T" "$(harness request composed)"; expect_denied "B2 one unlisted callee" "call to get"
  T="$(policy ows-e2e-cc-tree-whole "{\"$CALLER.write_then_read\": {}, \"$TALLY.set\": {}, \"$TALLY.get\": {}}")"
  step "B2 the tree with every call listed" "OWS_PASSPHRASE=<token> ows sign tx …"
  sign "$T" "$(harness request composed)"; expect_signed "B2 whole tree listed"

  T="$(policy ows-e2e-cc-pin "{\"$SINGLE.record\": {\"verifier_key\": \"$(printf '00%.0s' {1..32})\"}}")"
  step "B3 a pinned verifier key the contract does not hold" "OWS_PASSPHRASE=<token> ows sign tx …"
  sign "$T" "$(harness request single)"; expect_denied "B3 verifier key pin" "is not the pinned"

  step "B4 a disclosure claiming record(12346) for a call proven with 12345" "ows sign tx …"
  sign "$PASS" "$(harness request single --amount 12345 --disclose lie)"
  if printf '%s' "$OUT" | grep -q "opens no call in the transaction"; then pass "B4 lying disclosure refused"
  else fail "B4 expected the disclosure to be refused: $(printf '%s' "$OUT" | tail -2)"; fi
fi

# ═══ C. Sponsorship ════════════════════════════════════════════════════════════════════════════
if part C; then
  say "C. A sponsored transaction passes through the wallet untouched"
  REQ="$(harness request single --amount 777 --pay-fees false)"
  UNSEALED="$(printf '%s' "$REQ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tx"])')"
  step "C sign with payFees:false" "ows sign tx --tx '{\"options\":{\"payFees\":false}, …}'"
  sign "$PASS" "$REQ"
  SEALED="$(printf '%s' "$OUT" | python3 -c '
import json,sys
s=sys.stdin.read(); d=json.loads(s[s.find("{"):])
print(d.get("transaction") or "")')"
  SIG="$(printf '%s' "$OUT" | python3 -c '
import json,sys
s=sys.stdin.read(); d=json.loads(s[s.find("{"):])
print(repr(d.get("signature")))')"
  if [ "$SIG" = "''" ]; then pass "C the wallet signed nothing"; else fail "C expected no signature, got $SIG"; fi
  if printf '%s' "$SEALED" | xxd -r -p | head -c 80 | grep -q 'pedersen-schnorr'; then pass "C returned sealed"
  else fail "C expected a sealed transaction"; fi
  # The sealed body must be the dapp's: same intents, same calls, nothing of the wallet's.
  if [ -n "$SEALED" ] && [ "${#SEALED}" -le $(( ${#UNSEALED} + 400 )) ]; then pass "C nothing added (${#UNSEALED} → ${#SEALED} hex chars, sealing only)"
  else fail "C the passed-through transaction grew (${#UNSEALED} → ${#SEALED})"; fi
  step "C a sponsor pays the fee by merging, and submits" \
    "ows sign send-tx --tx '{\"method\":\"balanceSealedTransaction\",\"makerTx\":\"<sealed>\"}'"
  if send "C sponsor" "$PASS" "{\"method\":\"balanceSealedTransaction\",\"makerTx\":\"$SEALED\"}" && [ -n "$HASH" ]; then
    landed "$HASH" 1 "C sponsored record(777)"
  else
    fail "C sponsor merge: $(first_error)"
  fi
fi

# ═══ D. The mempool wall ═══════════════════════════════════════════════════════════════════════
if part D; then
  say "D. A wallet that can only pay by registration is refused before proving, naming the wall"
  FRESH="e2e-wall-$(date +%Y%m%d-%H%M%S)"
  # A registration pays from DUST the NIGHT has generated since its block: 8267 specks per star per
  # second, so 300 NIGHT covers a call's fee within two minutes.
  step "D create $FRESH and send it 300 NIGHT" "ows wallet create --name $FRESH; ows sign send-tx --tx '{makeTransfer 300 NIGHT}'"
  "$OWS" wallet create --name "$FRESH" >/dev/null || fail "D could not create $FRESH"
  MAINNET_ADDR="$("$OWS" wallet list 2>/dev/null | awk -v n="$FRESH" '/^Name:/{w=($2==n)} w && /midnight:mainnet/{print $NF; exit}')"
  FRESH_ADDR="$(harness on-network "$MAINNET_ADDR")"
  TRANSFER="{\"method\":\"makeTransfer\",\"desiredOutputs\":[{\"kind\":\"unshielded\",\"type\":\"night\",\"value\":\"300000000\",\"recipient\":\"$FRESH_ADDR\"}]}"
  if send "D fund" "$PASS" "$TRANSFER" && [ -n "$HASH" ]; then
    harness wait "$HASH" >/dev/null
    step "D fund record(1) from $FRESH, which can only pay by registration" "ows sign send-tx --wallet $FRESH --tx \"\$(… request single)\""
    # Until the NIGHT has generated the fee, there is no registration to refuse: wait it out.
    for attempt in 1 2 3 4 5 6 7 8; do
      sleep 30
      OUT="$(OWS_PASSPHRASE="" "$OWS" sign send-tx --wallet "$FRESH" --chain "$CHAIN" --json --tx "$(harness request single --amount 1)" 2>&1)"
      printf '%s' "$OUT" | grep -q "OutsideTimeToDismiss" && break
      note "  attempt $attempt: $(first_error) — the NIGHT has not generated the fee yet"
    done
    if printf '%s' "$OUT" | grep -q "OutsideTimeToDismiss" && printf '%s' "$OUT" | grep -q "paying it with a DUST spend instead"; then
      pass "D refused before proving, naming the wall: $(printf '%s' "$OUT" | grep -oE 'it takes [^,]+, a [0-9]+-byte transaction may take at most [0-9.]+ms' | head -1)"
    else
      fail "D expected the OutsideTimeToDismiss refusal: $(first_error)"
    fi
  else
    fail "D could not fund $FRESH: $(first_error)"
  fi
fi

# ═══ E. DUST spend proofs ══════════════════════════════════════════════════════════════════════
if part E; then
  # Each funding starts the moment the previous one lands: the block that lands it changes the dust
  # trees, which is when a DUST spend proved from one indexer read and timed from another was refused.
  say "E. $E_RUNS fundings, each as soon as the last lands; none refused for its DUST spend proof (170)"
  REFUSED=0
  for i in $(seq 1 "$E_RUNS"); do
    if send "E $i" "$PASS" "$(harness request single --amount "$i")" && [ -n "$HASH" ]; then
      harness wait "$HASH" >/dev/null && note "  $i: $HASH landed"
    elif printf '%s' "$OUT" | grep -q "Custom error: 170"; then
      REFUSED=$((REFUSED + 1)); note "  $i: ledger error 170"
    else
      fail "E $i: $(first_error)"
    fi
  done
  if [ "$REFUSED" = 0 ]; then pass "E $E_RUNS fundings, no error 170"; else fail "E $REFUSED of $E_RUNS refused with error 170"; fi
fi

say "Result: $PASSED passed, $FAILED failed"
for f in "${FAILURES[@]:-}"; do [ -n "$f" ] && printf '%s  ✗ %s%s\n' "$RED" "$f" "$RESET"; done
[ "$FAILED" = 0 ]
