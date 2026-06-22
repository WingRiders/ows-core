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
