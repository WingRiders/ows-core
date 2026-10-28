// The dapp side of the contract-call e2e: compiled test contracts, midnight-js providers, deploying
// through OWS, and building a proven, unbalanced call transaction plus the disclosure of every call
// in it — the `balanceUnsealedTransaction` request a dapp hands the wallet.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import * as rt from "@midnight-ntwrk/compact-runtime";
import { CompiledContract } from "@midnight-ntwrk/compact-js";
import {
  createUnprovenCallTxFromInitialStates,
  createUnprovenDeployTxFromVerifierKeys,
} from "@midnight-ntwrk/midnight-js-contracts";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import {
  NodeZkConfigProvider,
  nodeZkConfigRegistry,
} from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import * as ledger from "@midnightntwrk/ledger-v9";

import * as Single from "../contracts/managed/Single/contract/index.js";
import * as Tally from "../contracts/managed/Tally/contract/index.js";
import * as Caller from "../contracts/managed/Caller/contract/index.js";
import * as Till from "../contracts/managed/Till/contract/index.js";
import * as Payer from "../contracts/managed/Payer/contract/index.js";
import * as Vault from "../contracts/managed/Vault/contract/index.js";

const ROOT = resolve(import.meta.dir, "..");
const MANAGED = resolve(ROOT, "contracts/managed");

export const NETWORK = process.env.NETWORK ?? "stagenet";
const INDEXER =
  process.env.INDEXER_URL ?? `https://indexer.${NETWORK}.shielded.tools/api/v4/graphql`;
const PROOF_SERVER_URL = process.env.PROOF_SERVER_URL ?? "http://localhost:6301";
const OWS = process.env.OWS ?? "ows";
const WALLET = process.env.WALLET ?? "";
const DEPLOYMENTS = resolve(ROOT, "out", `deployments.${NETWORK}.json`);

const MODULES = { Single, Tally, Caller, Till, Payer, Vault } as const;
export type ContractName = keyof typeof MODULES;
export const CONTRACTS = Object.keys(MODULES) as ContractName[];

const NIGHT = new Uint8Array(32);

export interface Case {
  contract: ContractName;
  circuit: string;
  amount: bigint;
  args: (amount: bigint) => unknown[];
}

// Every case moves `amount` of something: a recorded number, a written value, NIGHT, or a shielded
// coin's value.
export const CASES: Record<string, Case> = {
  // Single.record(amount: Uint<64>, tag: Bytes<32>): Uint<64> — one call, no value.
  single: {
    contract: "Single",
    circuit: "record",
    amount: 12345n,
    args: (amount) => [amount, Uint8Array.from({ length: 32 }, (_, i) => i + 1)],
  },
  // Caller.write_then_read(x) calls Tally.set(x) and Tally.get(): three calls, no value.
  composed: {
    contract: "Caller",
    circuit: "write_then_read",
    amount: 42n,
    args: (amount) => [amount],
  },
  // Payer.pay_from_wallet takes NIGHT in, pays it to the Till and drives Till.take_unshielded.
  value: {
    contract: "Payer",
    circuit: "pay_from_wallet",
    amount: 1_000_000n,
    args: (amount) => [NIGHT, amount],
  },
  // Payer.forward_from_wallet drives Till.take_unshielded; only the sub-call takes NIGHT in.
  "value-forward": {
    contract: "Payer",
    circuit: "forward_from_wallet",
    amount: 1_000_000n,
    args: (amount) => [NIGHT, amount],
  },
  // Vault.deposit_shielded(coin): the dapp outputs a coin to the vault, which claims it.
  shielded: {
    contract: "Vault",
    circuit: "deposit_shielded",
    amount: 1000n,
    args: (amount) => [
      ledger.encodeShieldedCoinInfo(ledger.createShieldedCoinInfo(shieldedColor(), amount)),
    ],
  },
};

function shieldedColor(): string {
  const color = process.env.SHIELDED_COLOR;
  if (!color) throw new Error("set SHIELDED_COLOR to a shielded token the wallet holds");
  return color;
}

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

function compiled(name: ContractName) {
  return CompiledContract.make(name, (MODULES[name] as any).Contract).pipe(
    CompiledContract.withVacantWitnesses,
    CompiledContract.withCompiledFileAssets(resolve(MANAGED, name)),
  ) as any;
}

async function providers() {
  setNetworkId(NETWORK as any);
  // Proving a call tree needs the keys of every contract in it, so keys resolve through a registry
  // over every compiled contract.
  const registry = await nodeZkConfigRegistry(MANAGED);
  return {
    publicData: indexerPublicDataProvider(INDEXER, INDEXER.replace(/^http/, "ws") + "/ws"),
    proof: httpClientProofProvider(PROOF_SERVER_URL, registry as any),
    zkConfig: (name: ContractName) => new NodeZkConfigProvider<string>(resolve(MANAGED, name)),
  };
}

// A call that makes no shielded output to the user needs no real Zswap keys.
function throwawayZswapKeys() {
  const keys = ledger.ZswapSecretKeys.fromSeed(crypto.getRandomValues(new Uint8Array(32)));
  const out = { coinPublicKey: keys.coinPublicKey, encryptionPublicKey: keys.encryptionPublicKey };
  keys.clear();
  return out;
}

// ── deployments ──────────────────────────────────────────────────────────────────────────────

function deployments(): Record<string, string> {
  return existsSync(DEPLOYMENTS) ? JSON.parse(readFileSync(DEPLOYMENTS, "utf8")) : {};
}

export function addressOf(name: ContractName): string {
  const address = deployments()[name];
  if (!address) throw new Error(`${name} is not deployed on ${NETWORK}; run: bun src/cli.ts deploy`);
  return address;
}

export async function isLive(address: string): Promise<boolean> {
  const body = await graphql(`query ($a: HexEncoded!) { contractAction(address: $a) { address } }`, {
    a: address,
  });
  return Boolean(body?.data?.contractAction);
}

function constructorArgs(name: ContractName): unknown[] {
  const ref = (n: ContractName) => ({ bytes: rt.encodeContractAddress(addressOf(n)) });
  if (name === "Caller") return [ref("Tally")];
  if (name === "Payer") return [ref("Till"), ref("Till")];
  return [];
}

// Deploy `name` through OWS (owner credential from OWS_PASSPHRASE), the way a dapp would: build and
// prove the deploy, hand the proven unsealed transaction to `ows sign send-tx`.
export async function deploy(name: ContractName): Promise<string> {
  const p = await providers();
  const keys = throwawayZswapKeys();
  const full = await createUnprovenDeployTxFromVerifierKeys(
    p.zkConfig(name),
    keys.coinPublicKey,
    { compiledContract: compiled(name), args: constructorArgs(name) } as any,
    keys.encryptionPublicKey,
  );
  const proven = await p.proof.proveTx(full.private.unprovenTx as any);
  const request = {
    method: "balanceUnsealedTransaction",
    tx: hex(proven.serialize()),
    options: { payFees: true },
  };
  const txHash = await owsSendTx(JSON.stringify(request));
  await waitForTx(txHash);
  const address: string = full.public.contractAddress;
  mkdirSync(resolve(DEPLOYMENTS, ".."), { recursive: true });
  writeFileSync(DEPLOYMENTS, JSON.stringify({ ...deployments(), [name]: address }, null, 2) + "\n");
  return address;
}

async function owsSendTx(request: string): Promise<string> {
  if (!WALLET) throw new Error("set WALLET to the OWS wallet that pays");
  const proc = Bun.spawn(
    [OWS, "sign", "send-tx", "--wallet", WALLET, "--chain", `midnight:${NETWORK}`, "--json", "--tx", request],
    { stdin: "ignore", stdout: "pipe", stderr: "inherit" },
  );
  const [stdout, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
  if (code !== 0) throw new Error(`ows sign send-tx exited with ${code}`);
  return JSON.parse(stdout).tx_hash;
}

// ── call requests ────────────────────────────────────────────────────────────────────────────

interface Captured {
  address: string;
  entryPoint: string;
  input: rt.AlignedValue;
  output: rt.AlignedValue;
  communicationCommitmentRand: string;
}

const wire = (value: rt.AlignedValue) => ({
  value: value.value.map((atom) => hex(atom)),
  alignment: value.alignment,
});

export interface RequestOptions {
  amount?: bigint;
  payFees: boolean;
  // Which calls' arguments to disclose: every call, none, or every call with the root's first
  // argument misstated (a disclosure that opens no call).
  disclose: "all" | "none" | "lie";
}

// Build and prove `caseName`'s call against the contracts' current state and return the
// `balanceUnsealedTransaction` request for it, unbalanced and unsealed, with its disclosure.
export async function request(caseName: string, options: RequestOptions) {
  const c = CASES[caseName];
  if (!c) throw new Error(`unknown case ${caseName}; cases: ${Object.keys(CASES).join(", ")}`);
  const amount = options.amount ?? c.amount;
  const p = await providers();
  const address = addressOf(c.contract);
  const block = await p.publicData.queryBlock();
  if (!block) throw new Error("the indexer returned no block");
  const states = await p.publicData.queryZSwapAndContractState(address, {
    type: "blockHash",
    blockHash: block.hash,
  });
  if (!states) throw new Error(`no contract at ${address}`);
  const [zswapChainState, contractState, ledgerParameters] = states;

  const args = c.args(amount);
  const captured: Captured[] = [];
  (globalThis as any).__captureCall = (call: Captured) => captured.push(call);
  const keys = throwawayZswapKeys();
  let built: any;
  try {
    built = await createUnprovenCallTxFromInitialStates(
      p.zkConfig(c.contract),
      {
        compiledContract: compiled(c.contract),
        contractAddress: address,
        circuitId: c.circuit,
        args,
        coinPublicKey: keys.coinPublicKey,
        initialContractState: contractState,
        initialZswapChainState: zswapChainState,
        ledgerParameters,
      } as any,
      keys.encryptionPublicKey,
      { publicDataProvider: p.publicData, blockHash: block.hash } as any,
    );
  } finally {
    (globalThis as any).__captureCall = undefined;
  }
  if (captured.length !== built.calls.length) {
    throw new Error(`captured ${captured.length} of ${built.calls.length} calls; run bun install`);
  }
  const proven = await p.proof.proveTx(built.private.unprovenTx);

  const calls = captured.map((call) => ({
    address: call.address,
    entryPoint: call.entryPoint,
    input: wire(call.input),
    output: wire(call.output),
    communicationCommitmentRand: call.communicationCommitmentRand,
  }));
  if (options.disclose === "lie") {
    // The root is captured last; claim its first argument was one more than it was.
    const root = calls[calls.length - 1]!;
    const first = BigInt("0x" + (Buffer.from(root.input.value[0]!, "hex").reverse().toString("hex") || "0"));
    root.input.value[0] = Buffer.from((first + 1n).toString(16).padStart(2, "0"), "hex").reverse().toString("hex");
  }
  const coins =
    caseName === "shielded"
      ? [
          {
            nonce: hex((args[0] as any).nonce),
            color: hex((args[0] as any).color),
            value: amount.toString(),
          },
        ]
      : [];
  return {
    method: "balanceUnsealedTransaction",
    tx: hex(proven.serialize()),
    options: { payFees: options.payFees },
    ...(options.disclose === "none" ? {} : { disclose: { calls, coins } }),
  };
}

// ── indexer ──────────────────────────────────────────────────────────────────────────────────

export async function graphql(query: string, variables: Record<string, unknown>): Promise<any> {
  const response = await fetch(INDEXER, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  return response.json();
}

// Wait until the indexer holds the transaction; returns its result and its contract calls.
export async function waitForTx(txHash: string, timeoutMs = 5 * 60_000): Promise<any> {
  const query = `query ($hash: HexEncoded!) {
    transactions(offset: { hash: $hash }) {
      hash
      block { height }
      contractActions { address ... on ContractCall { entryPoint } }
      ... on RegularTransaction { transactionResult { status } }
    }
  }`;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const body = await graphql(query, { hash: txHash.replace(/^0x/, "") });
    const tx = body?.data?.transactions?.[0];
    if (tx) return tx;
    await Bun.sleep(4_000);
  }
  throw new Error(`the indexer does not show ${txHash} after ${timeoutMs / 1000}s`);
}
