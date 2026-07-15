import * as path from "path";
import * as snarkjs from "snarkjs";
import { PoseidonMerkleTree, commitment, poseidonHash } from "./crypto";

const BUILD = path.resolve(__dirname, "..", "build");
const WASM = path.join(BUILD, "ownership_js", "ownership.wasm");
const ZKEY = path.join(BUILD, "ownership_final.zkey");

// publicSignals ordering (snarkjs: outputs first, then public inputs in
// declaration order): [nullifier, root, parcelId, challenge]
export const SIG = { nullifier: 0, root: 1, parcelId: 2, challenge: 3 } as const;

export interface Groth16Proof {
  proof: any;
  publicSignals: string[];
}

export interface OwnershipWitness {
  ownerSecret: bigint;
  salt: bigint;
  parcelId: bigint;
  pathElements: bigint[];
  pathIndices: number[];
  root: bigint;
  challenge: bigint;
}

// Prover: run entirely by the OWNER, off-chain. PII never leaves here.
export async function proveOwnership(w: OwnershipWitness): Promise<Groth16Proof> {
  const input = {
    ownerSecret: w.ownerSecret.toString(),
    salt: w.salt.toString(),
    parcelId: w.parcelId.toString(),
    pathElements: w.pathElements.map((x) => x.toString()),
    pathIndices: w.pathIndices.map((x) => x.toString()),
    root: w.root.toString(),
    challenge: w.challenge.toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { proof, publicSignals };
}

// Verifier: consumes vkey (from on-chain state) + proof + public signals only.
export async function verifyOwnershipProof(vkey: any, p: Groth16Proof): Promise<boolean> {
  return snarkjs.groth16.verify(vkey, p.publicSignals, p.proof);
}

export function nullifierOf(p: Groth16Proof): bigint { return BigInt(p.publicSignals[SIG.nullifier]); }
export function rootOf(p: Groth16Proof): bigint { return BigInt(p.publicSignals[SIG.root]); }
export function parcelOf(p: Groth16Proof): bigint { return BigInt(p.publicSignals[SIG.parcelId]); }
export function challengeOf(p: Groth16Proof): bigint { return BigInt(p.publicSignals[SIG.challenge]); }

// Build the witness given a tree + the owner's secrets + verifier challenge.
export async function buildWitness(
  tree: PoseidonMerkleTree,
  leafIndex: number,
  ownerSecret: bigint,
  parcelId: bigint,
  salt: bigint,
  challenge: bigint
): Promise<OwnershipWitness> {
  const c = await commitment(ownerSecret, parcelId, salt);
  const mp = tree.proof(leafIndex);
  if (c !== mp.leaf) {
    throw new Error("commitment mismatch: secrets do not correspond to that leaf");
  }
  return {
    ownerSecret,
    salt,
    parcelId,
    pathElements: mp.pathElements,
    pathIndices: mp.pathIndices,
    root: mp.root,
    challenge,
  };
}

// Expected nullifier for a given secret+challenge (owner-side sanity / tests).
export async function expectedNullifier(ownerSecret: bigint, challenge: bigint): Promise<bigint> {
  return poseidonHash([ownerSecret, challenge]);
}
