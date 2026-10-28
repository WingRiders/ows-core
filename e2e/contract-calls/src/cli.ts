// bun src/cli.ts deploy [--force]
//     Deploy every test contract not yet live on NETWORK through OWS (WALLET pays, OWS_PASSPHRASE).
// bun src/cli.ts request <case> [--amount N] [--pay-fees false] [--disclose all|none|lie]
//     Print the balanceUnsealedTransaction request for one call: proven, unbalanced, with the
//     disclosure of every call in it. Cases: single, composed, value, value-forward, shielded.
// bun src/cli.ts address <Contract>
//     Print a deployed contract's address.
// bun src/cli.ts wait <tx-hash>
//     Wait for the indexer to hold a transaction; print its result and its contract calls.
// bun src/cli.ts on-network <mn_addr1…>
//     Print an unshielded address as NETWORK writes it (`ows wallet list` shows mainnet's).

import { bech32m } from "@scure/base";
import {
  CONTRACTS,
  NETWORK,
  addressOf,
  deploy,
  isLive,
  request,
  waitForTx,
  type ContractName,
} from "./harness.ts";

const [command, ...rest] = Bun.argv.slice(2);
const flag = (name: string) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? rest[i + 1] : undefined;
};

switch (command) {
  case "deploy": {
    for (const name of CONTRACTS) {
      const known = (() => {
        try {
          return addressOf(name);
        } catch {
          return undefined;
        }
      })();
      if (known && !rest.includes("--force") && (await isLive(known))) {
        console.error(`${name}: live at ${known}`);
        continue;
      }
      console.error(`${name}: deploying through OWS…`);
      console.error(`${name}: deployed at ${await deploy(name)}`);
    }
    break;
  }
  case "request": {
    const amount = flag("amount");
    const body = await request(rest[0]!, {
      amount: amount === undefined ? undefined : BigInt(amount),
      payFees: flag("pay-fees") !== "false",
      disclose: (flag("disclose") ?? "all") as "all" | "none" | "lie",
    });
    process.stdout.write(JSON.stringify(body));
    break;
  }
  case "address":
    console.log(addressOf(rest[0] as ContractName));
    break;
  case "wait":
    console.log(JSON.stringify(await waitForTx(rest[0]!)));
    break;
  case "on-network": {
    const { words } = bech32m.decode(rest[0]! as `${string}1${string}`, 1000);
    console.log(bech32m.encode(NETWORK === "mainnet" ? "mn_addr" : `mn_addr_${NETWORK}`, words, 1000));
    break;
  }
  default:
    console.error(
      "usage: bun src/cli.ts deploy | request <case> | address <Contract> | wait <tx-hash> | on-network <address>",
    );
    process.exit(2);
}
process.exit(0);
