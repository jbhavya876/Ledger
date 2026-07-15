// Off-chain proof generator for the Fabric client flow.
// Usage: tsx scripts/gen_proof.ts <parcelId> <ownerSecret> <salt> <leafIndex> <challenge> <pathJson>
// pathJson = {"root":"..","pathElements":[..],"pathIndices":[..]} from GetMerklePath.
// Prints proof JSON ({proof, publicSignals}) to stdout.
import * as path from "path";
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";

const BUILD = path.resolve(__dirname, "..", "build");
const WASM = path.join(BUILD, "ownership_js", "ownership.wasm");
const ZKEY = path.join(BUILD, "ownership_final.zkey");

async function poseidonField(inputs: bigint[]): Promise<bigint> {
  const p = await buildPoseidon();
  return BigInt(p.F.toString(p(inputs)));
}
async function parcelToField(parcelId: string): Promise<bigint> {
  let acc = 0n;
  for (const ch of parcelId) acc = acc * 256n + BigInt(ch.charCodeAt(0));
  return poseidonField([acc]);
}

async function main() {
  const [parcelId, ownerSecret, salt, _leafIndex, challenge, pathJson] = process.argv.slice(2);
  const p = JSON.parse(pathJson) as { root: string; pathElements: string[]; pathIndices: number[] };
  const parcelField = await parcelToField(parcelId);

  const input = {
    ownerSecret,
    salt,
    parcelId: parcelField.toString(),
    pathElements: p.pathElements,
    pathIndices: p.pathIndices.map(String),
    root: p.root,
    challenge,
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  process.stdout.write(JSON.stringify({ proof, publicSignals }));
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
