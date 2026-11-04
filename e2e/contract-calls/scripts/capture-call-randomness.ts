// Runs as postinstall. midnight-js draws a root call's communication-commitment randomness inside
// createUnprovenLedgerCallTx and never returns it, so the one place to learn the exact (input,
// output, rand) a call was built with is the ContractCallPrototype constructor it feeds. This hooks
// that single site in @midnight-ntwrk/midnight-js-contracts: when globalThis.__captureCall is a
// function, every call's triple is handed to it — the disclosure OWS checks against the proven
// transaction. Inert otherwise. Idempotent.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const file = resolve(
  import.meta.dir,
  "..",
  "node_modules/@midnight-ntwrk/midnight-js-contracts/dist/index.js",
);
const MARK = "/* ows e2e: capture call randomness */";
let src = readFileSync(file, "utf8");
if (src.includes(MARK)) process.exit(0);

const before = `        intent = intent.addCall(new ContractCallPrototype(call.contractAddress, call.circuitId, op, call.public.partitionedTranscript[0], call.public.partitionedTranscript[1], call.private.privateTranscriptOutputs, call.private.input, call.private.output, Option.match(call.communicationCommitment, {
            onSome: (commitment) => commitment.commCommRand,
            onNone: () => communicationCommitmentRandomness()
        }), encodeContractKeyLocation({`;

const after = `        ${MARK}
        const __rand = Option.match(call.communicationCommitment, {
            onSome: (commitment) => commitment.commCommRand,
            onNone: () => communicationCommitmentRandomness()
        });
        if (typeof globalThis.__captureCall === 'function') {
            globalThis.__captureCall({
                address: call.contractAddress,
                entryPoint: call.circuitId,
                input: call.private.input,
                output: call.private.output,
                communicationCommitmentRand: __rand
            });
        }
        intent = intent.addCall(new ContractCallPrototype(call.contractAddress, call.circuitId, op, call.public.partitionedTranscript[0], call.public.partitionedTranscript[1], call.private.privateTranscriptOutputs, call.private.input, call.private.output, __rand, encodeContractKeyLocation({`;

if (src.split(before).length !== 2) {
  throw new Error("expected exactly one ContractCallPrototype site; midnight-js changed");
}
writeFileSync(file, src.replace(before, after));
