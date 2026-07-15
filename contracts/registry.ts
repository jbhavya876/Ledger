import { PoseidonMerkleTree, commitment, poseidonHash } from "./crypto";
import {
  Groth16Proof,
  verifyOwnershipProof,
  nullifierOf,
  rootOf,
  parcelOf,
  challengeOf,
} from "./zk";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

// ---------------------------------------------------------------------------
// LedgerX Registry Contract (Phase 1, hardened; Fabric-shaped).
//
// Hardening vs. v1:
//   * Verification key stored in world state (registry:vkey), not read from
//     disk at verify time -> mirrors Fabric, VK becomes consensus-checked.
//   * Anti-replay: verifier issues a single-use `challenge`; the proof is
//     cryptographically bound to it. On success the challenge is consumed and
//     the proof's nullifier is recorded. Replaying the same proof re-presents a
//     spent challenge + seen nullifier -> rejected.
// ---------------------------------------------------------------------------

export interface Title {
  parcelId: string;
  commitment: string;
  leafIndex: number;
  status: "ACTIVE" | "PENDING_TRANSFER";
  createdAt: number;
  version: number;
}

export interface TransferRequest {
  parcelId: string;
  newCommitment: string;
  requiredEndorsers: string[];
  endorsements: Record<string, boolean>;
  status: "PENDING" | "APPROVED" | "COMMITTED" | "REJECTED";
  createdAt: number;
}

export class KVStore {
  private m = new Map<string, string>();
  async putState(k: string, v: string) { this.m.set(k, v); }
  async getState(k: string): Promise<string | undefined> { return this.m.get(k); }
  async deleteState(k: string) { this.m.delete(k); }
  async *range(prefix: string): AsyncGenerator<[string, string]> {
    for (const [k, v] of this.m) if (k.startsWith(prefix)) yield [k, v];
  }
}

const TITLE = (id: string) => `title:${id}`;
const XFER = (id: string) => `xfer:${id}`;
const ROOT_KEY = "registry:merkleRoot";
const VKEY_KEY = "registry:vkey";
const CHALLENGE = (id: string) => `challenge:${id}`;   // pending challenge per parcel
const NULLIFIER = (n: string) => `nullifier:${n}`;      // spent nullifiers

export class LedgerXRegistry {
  private tree!: PoseidonMerkleTree;

  constructor(private readonly db: KVStore, private readonly treeDepth = 10) {}

  async init(vkey?: any): Promise<void> {
    this.tree = await PoseidonMerkleTree.create(this.treeDepth, []);
    await this.db.putState(ROOT_KEY, this.tree.root.toString());
    // Store the verification key on-chain. Default: load from build/ (bootstrap).
    const vk = vkey ?? JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "..", "build", "verification_key.json"), "utf8")
    );
    await this.db.putState(VKEY_KEY, JSON.stringify(vk));
  }

  get merkleTree(): PoseidonMerkleTree { return this.tree; }

  async getRoot(): Promise<bigint> {
    const r = await this.db.getState(ROOT_KEY);
    return BigInt(r ?? "0");
  }

  async getVerificationKey(): Promise<any> {
    const raw = await this.db.getState(VKEY_KEY);
    if (!raw) throw new Error("verification key not initialised on-chain");
    return JSON.parse(raw);
  }

  // --- Mint ---
  async mintTitle(parcelId: string, commitmentHex: string): Promise<Title> {
    if (await this.db.getState(TITLE(parcelId))) {
      throw new Error(`title ${parcelId} already exists`);
    }
    const leaf = BigInt(commitmentHex);
    const leafIndex = await this.tree.insert(leaf);
    await this.db.putState(ROOT_KEY, this.tree.root.toString());
    const title: Title = {
      parcelId, commitment: commitmentHex, leafIndex,
      status: "ACTIVE", createdAt: Date.now(), version: 1,
    };
    await this.db.putState(TITLE(parcelId), JSON.stringify(title));
    return title;
  }

  async getTitle(parcelId: string): Promise<Title | undefined> {
    const raw = await this.db.getState(TITLE(parcelId));
    return raw ? (JSON.parse(raw) as Title) : undefined;
  }

  // --- Multi-party endorsed transfer ---
  async initiateTransfer(parcelId: string, newCommitmentHex: string, requiredEndorsers: string[]): Promise<TransferRequest> {
    const title = await this.getTitle(parcelId);
    if (!title) throw new Error(`no such title ${parcelId}`);
    if (title.status !== "ACTIVE") throw new Error(`title ${parcelId} not transferable (${title.status})`);
    if (requiredEndorsers.length === 0) throw new Error("at least one endorser required");
    title.status = "PENDING_TRANSFER";
    await this.db.putState(TITLE(parcelId), JSON.stringify(title));
    const req: TransferRequest = {
      parcelId, newCommitment: newCommitmentHex, requiredEndorsers,
      endorsements: {}, status: "PENDING", createdAt: Date.now(),
    };
    await this.db.putState(XFER(parcelId), JSON.stringify(req));
    return req;
  }

  async endorseTransfer(parcelId: string, endorserMSP: string, approve: boolean): Promise<TransferRequest> {
    const raw = await this.db.getState(XFER(parcelId));
    if (!raw) throw new Error(`no pending transfer for ${parcelId}`);
    const req = JSON.parse(raw) as TransferRequest;
    if (req.status !== "PENDING") throw new Error(`transfer for ${parcelId} is ${req.status}`);
    if (!req.requiredEndorsers.includes(endorserMSP)) throw new Error(`${endorserMSP} is not a required endorser`);
    req.endorsements[endorserMSP] = approve;
    if (approve === false) {
      req.status = "REJECTED";
      const title = (await this.getTitle(parcelId))!;
      title.status = "ACTIVE";
      await this.db.putState(TITLE(parcelId), JSON.stringify(title));
    } else if (req.requiredEndorsers.every((e) => req.endorsements[e] === true)) {
      req.status = "APPROVED";
    }
    await this.db.putState(XFER(parcelId), JSON.stringify(req));
    return req;
  }

  async commitTransfer(parcelId: string): Promise<Title> {
    const raw = await this.db.getState(XFER(parcelId));
    if (!raw) throw new Error(`no transfer for ${parcelId}`);
    const req = JSON.parse(raw) as TransferRequest;
    if (req.status !== "APPROVED") throw new Error(`endorsement policy not satisfied for ${parcelId} (status ${req.status})`);
    const title = (await this.getTitle(parcelId))!;
    // Overwrite the seller's leaf in place: their old commitment leaves the tree,
    // so any pre-transfer ownership proof they hold stops verifying.
    await this.tree.updateLeaf(title.leafIndex, BigInt(req.newCommitment));
    title.commitment = req.newCommitment;
    title.status = "ACTIVE";
    title.version += 1;
    await this.db.putState(TITLE(parcelId), JSON.stringify(title));
    await this.db.putState(ROOT_KEY, this.tree.root.toString());
    req.status = "COMMITTED";
    await this.db.putState(XFER(parcelId), JSON.stringify(req));
    return title;
  }

  // --- Anti-replay ownership verification ---------------------------------

  // Step 1: verifier issues a single-use challenge for a parcel.
  async issueChallenge(parcelId: string): Promise<bigint> {
    if (!(await this.getTitle(parcelId))) throw new Error(`no such title ${parcelId}`);
    // random field element (< BN254 scalar field); 31 bytes is safely in-field
    const challenge = BigInt("0x" + crypto.randomBytes(31).toString("hex"));
    await this.db.putState(CHALLENGE(parcelId), challenge.toString());
    return challenge;
  }

  // Step 2: verify a proof produced for the issued challenge. Single-use.
  async verifyOwnership(parcelId: string, proof: Groth16Proof): Promise<boolean> {
    // a) parcel binding
    if (parcelOf(proof) !== await parcelToField(parcelId)) return false;
    // b) root freshness
    if (rootOf(proof) !== await this.getRoot()) return false;
    // c) challenge must match the pending single-use challenge
    const pending = await this.db.getState(CHALLENGE(parcelId));
    if (!pending) return false;                       // no challenge issued / already consumed
    if (challengeOf(proof) !== BigInt(pending)) return false;
    // d) nullifier must be unseen (blocks replay even within same challenge window)
    const nf = nullifierOf(proof).toString();
    if (await this.db.getState(NULLIFIER(nf))) return false;
    // e) cryptographic verification against ON-CHAIN vkey
    const vkey = await this.getVerificationKey();
    const ok = await verifyOwnershipProof(vkey, proof);
    if (!ok) return false;
    // consume: burn the challenge + record the nullifier (single-use)
    await this.db.deleteState(CHALLENGE(parcelId));
    await this.db.putState(NULLIFIER(nf), "1");
    return true;
  }
}

export async function parcelToField(parcelId: string): Promise<bigint> {
  let acc = 0n;
  for (const ch of parcelId) acc = acc * 256n + BigInt(ch.charCodeAt(0));
  return poseidonHash([acc]);
}
