# Midnight atomic swap via `makeIntent` (OWS)

Cross-domain moves (unshielded NIGHT in → shielded NIGHT out) use the [DApp Connector swap
pattern](https://github.com/midnightntwrk/midnight-dapp-connector-api/blob/main/docs/api/_media/SPECIFICATION.md):
an **imbalanced** `makeIntent` from party #1, then **`balanceSealedTransaction`** from party #2
before submit.

Do **not** use `ows sign send-tx` on the offer alone — the node rejects imbalanced txs with error
**138** (`BalanceCheckOverspend`). Use **`ows sign tx`** to produce sealed hex and share it with the
counterparty (or a service that runs `balanceSealedTransaction`).

## Party #1 — create the swap offer

Replace `SHIELDED_ADDR` with your preview shielded address (`ows accounts` / wallet shielded HRP
`mn_shield-addr_preview1…`). Amounts are in smallest units (e.g. `10000000` = 0.01 NIGHT if
6 decimals).

```bash
ows sign tx \
  --wallet YOUR_WALLET \
  --chain 'midnight:preview' \
  --tx '{"method":"makeIntent","desiredInputs":[{"kind":"unshielded","type":"night","value":10000000}],"desiredOutputs":[{"kind":"shielded","type":"night","value":10000000,"recipient":"SHIELDED_ADDR"}],"options":{"intentId":1,"payFees":true}}'
```

Save the `signature` hex from the output (full sealed wire). That is the imbalanced offer for party #2.

## MIP-0006 offer payloads

[MIP-0006](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/main/mips/mip-0006-p2p-atomic-swaps.md)
defines a portable swap offer JSON shape (often with a bare [`zswapoffer1…`](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/main/mips/mip-0005-zswap-offer-encoding.md)
bech32 in the `transaction` field). OWS validates this before balancing:

| Check | Behavior |
|-------|----------|
| `version` | Must be `1` |
| `gives` / `wants` | Compared to Zswap offer deltas (positive = maker gives, negative = maker wants) |
| `auth` (optional) | `schnorr-bip340` over RFC 8785 canonical JSON (SHA-256 digest) |
| `transaction` | `zswapoffer…` bech32, or sealed/proven Midnight hex |

Pass the full JSON as `--tx` (or inside `balanceSealedTransaction` via the dapp connector parser):

```bash
ows sign send-tx \
  --wallet YOUR_WALLET \
  --chain 'midnight:preview' \
  --tx '{"version":1,"transaction":"zswapoffer1…","gives":[{"token":"0x…","amount":"500000"}],"wants":[{"token":"0x…","amount":"500000"}]}'
```

Mismatched `gives`/`wants` or invalid `auth` are rejected before any proving or signing.

### Export `zswapoffer` from a maker sealed tx

After party #1 runs `ows sign tx` on an imbalanced shielded `makeIntent`, export MIP-0006 JSON:

```bash
ows sign export-mip6-offer \
  --chain 'midnight:preview' \
  --tx MAKER_SEALED_HEX \
  --json
```

This extracts the Zswap offer, encodes it as `zswapoffer1…` bech32 (MIP-0005) when the offer is
compact enough for bech32, otherwise embeds the full maker sealed/proven hex in `transaction`
(still valid MIP-0006). `gives` / `wants` are always derived from offer deltas.

Shielded-only maker example (party #1 gives custom token A, wants custom token B):

```bash
ows sign tx \
  --wallet YOUR_WALLET \
  --chain 'midnight:preview' \
  --tx '{"method":"makeIntent","desiredInputs":[{"kind":"shielded","type":"0xTOKEN_A","value":1000}],"desiredOutputs":[{"kind":"shielded","type":"0xTOKEN_B","value":1000,"recipient":"YOUR_SHIELDED_ADDR"}],"options":{"intentId":1,"payFees":false}}'
```

## Party #2 — balance and submit

Party #2 completes the swap with OWS using the same connector shape as Lace:

```bash
ows sign send-tx \
  --wallet YOUR_WALLET \
  --chain 'midnight:preview' \
  --tx '{"method":"balanceSealedTransaction","tx":"MAKER_SEALED_HEX","options":{"payFees":true}}'
```

You can also pass the maker sealed hex directly (or a `zswapoffer1…` bech32 string / MIP-0006 JSON
payload with a `transaction` field) as `--tx` when running `sign send-tx` or `sign tx`.

Requirements for the taker wallet:

- **Shielded seed** (mnemonic wallet) when the offer moves shielded tokens
- **Dust seed** on Preview/Preprod when `payFees` is true (default)

In a browser wallet (Lace, etc.) connected to the same network:

1. Obtain party #1’s sealed transaction hex.
2. Call `balanceSealedTransaction(tx, { payFees: true })`.
3. Call `submitTransaction(balancedTx)`.

OWS implements `balanceSealedTransaction` via `sign send-tx` / the JSON form above.

## Same-token vs custom token

The connector spec example swaps unshielded NIGHT for a **custom** shielded token. The JSON shape
is the same for unshielded NIGHT → shielded NIGHT (`"type":"night"` on both sides), as in the
command above.

## Self-contained alternatives (no counterparty)

| Goal | Approach |
|------|----------|
| Send shielded NIGHT you already hold | `makeIntent` with **shielded inputs + shielded outputs** (same value), shielded seed required |
| Send unshielded NIGHT | `makeTransfer` with unshielded `desiredOutputs` only |
| Shield unshielded NIGHT alone | Not one `sign send-tx`; requires swap counterparty via `balanceSealedTransaction` |
