import { Context, Contract, Info, Transaction, Returns } from "fabric-contract-api";
import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";

// ---------------------------------------------------------------------------
// LedgerX chaincode (Phase 2). Same logic as contracts/registry.ts, ported to
// Fabric: KVStore -> ctx.stub, methods -> @Transaction. Endorsement across
// Org1+Org2 is enforced by the channel endorsement policy (AND), not app code.
//
// Determinism: the Poseidon Merkle tree is NOT held in memory. Leaves live in
// world state (leaf:<idx>) and the tree is rebuilt from committed leaves for
// each mutation so every endorsing peer computes an identical root.
// ---------------------------------------------------------------------------

const DEPTH = 10;

let _poseidon: any = null;
async function poseidon() { if (!_poseidon) _poseidon = await buildPoseidon(); return _poseidon; }
async function H(inputs: (bigint | number | string)[]): Promise<bigint> {
  const p = await poseidon();
  return BigInt(p.F.toString(p(inputs.map((x) => BigInt(x)))));
}

// State keys
const TITLE = (id: string) => `title:${id}`;
const XFER = (id: string) => `xfer:${id}`;
const LEAF = (i: number) => `leaf:${i}`;
const LEAFCOUNT = "registry:leafcount";
const ROOT = "registry:merkleRoot";
const VKEY = "registry:vkey";
const CHALLENGE = (id: string) => `challenge:${id}`;
const NULLIFIER = (n: string) => `nullifier:${n}`;

interface Title {
  parcelId: string; commitment: string; leafIndex: number;
  status: "ACTIVE" | "PENDING_TRANSFER"; version: number;
}
interface TransferRequest {
  parcelId: string; newCommitment: string; requiredEndorsers: string[];
  endorsements: Record<string, boolean>;
  status: "PENDING" | "APPROVED" | "COMMITTED" | "REJECTED";
}

@Info({ title: "LedgerXRegistry", description: "Permissioned land registry with ZK ownership proofs" })
export class LedgerXContract extends Contract {

  // ---- helpers -----------------------------------------------------------
  private async getJSON<T>(ctx: Context, key: string): Promise<T | undefined> {
    const b = await ctx.stub.getState(key);
    return b && b.length ? (JSON.parse(b.toString()) as T) : undefined;
  }
  private async putJSON(ctx: Context, key: string, v: unknown): Promise<void> {
    await ctx.stub.putState(key, Buffer.from(JSON.stringify(v)));
  }
  private async leafCount(ctx: Context): Promise<number> {
    const b = await ctx.stub.getState(LEAFCOUNT);
    return b && b.length ? parseInt(b.toString(), 10) : 0;
  }

  // Rebuild the tree; return root + (optional) path. If `leavesOverride` is
  // given, use it instead of reading state (needed within a write tx, since
  // Fabric getState does NOT see this tx's own pending writes).
  private async computeTree(ctx: Context, wantPathFor?: number, leavesOverride?: bigint[]):
    Promise<{ root: bigint; pathElements: bigint[]; pathIndices: number[] }> {
    let leaves: bigint[];
    if (leavesOverride) {
      leaves = leavesOverride;
    } else {
      const n = await this.leafCount(ctx);
      leaves = [];
      for (let i = 0; i < n; i++) {
        const b = await ctx.stub.getState(LEAF(i));
        leaves.push(b && b.length ? BigInt(b.toString()) : 0n);
      }
    }
    // precompute zeros
    const zeros: bigint[] = [0n];
    for (let d = 0; d < DEPTH; d++) zeros.push(await H([zeros[d], zeros[d]]));

    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let idx = wantPathFor ?? -1;
    let cur = leaves.slice();
    for (let d = 0; d < DEPTH; d++) {
      if (idx >= 0) {
        const isRight = idx % 2 === 1;
        const sib = isRight ? idx - 1 : idx + 1;
        pathElements.push(sib < cur.length ? cur[sib] : zeros[d]);
        pathIndices.push(isRight ? 1 : 0);
        idx = Math.floor(idx / 2);
      }
      const next: bigint[] = [];
      for (let i = 0; i < cur.length; i += 2) {
        const l = cur[i], r = i + 1 < cur.length ? cur[i + 1] : zeros[d];
        next.push(await H([l, r]));
      }
      if (next.length === 0) next.push(zeros[d + 1]);
      cur = next;
    }
    return { root: cur[0], pathElements, pathIndices };
  }

  private async refreshRoot(ctx: Context): Promise<bigint> {
    const { root } = await this.computeTree(ctx);
    await ctx.stub.putState(ROOT, Buffer.from(root.toString()));
    return root;
  }

  // ---- lifecycle ---------------------------------------------------------
  @Transaction()
  async InitLedger(ctx: Context, vkeyJson: string): Promise<void> {
    await ctx.stub.putState(LEAFCOUNT, Buffer.from("0"));
    await this.refreshRoot(ctx);
    await ctx.stub.putState(VKEY, Buffer.from(vkeyJson)); // VK committed to state
  }

  @Transaction()
  @Returns("string")
  async MintTitle(ctx: Context, parcelId: string, commitmentHex: string): Promise<string> {
    if (await ctx.stub.getState(TITLE(parcelId)).then((b) => b && b.length)) {
      throw new Error(`title ${parcelId} already exists`);
    }
    const idx = await this.leafCount(ctx);
    await ctx.stub.putState(LEAF(idx), Buffer.from(BigInt(commitmentHex).toString()));
    await ctx.stub.putState(LEAFCOUNT, Buffer.from(String(idx + 1)));
    const title: Title = { parcelId, commitment: commitmentHex, leafIndex: idx, status: "ACTIVE", version: 1 };
    await this.putJSON(ctx, TITLE(parcelId), title);
    await this.refreshRoot(ctx);
    return JSON.stringify(title);
  }

  @Transaction(false)
  @Returns("string")
  async ReadTitle(ctx: Context, parcelId: string): Promise<string> {
    const t = await this.getJSON<Title>(ctx, TITLE(parcelId));
    if (!t) throw new Error(`no such title ${parcelId}`);
    return JSON.stringify(t);
  }

  @Transaction(false)
  @Returns("string")
  async GetRoot(ctx: Context): Promise<string> {
    const b = await ctx.stub.getState(ROOT);
    return b && b.length ? b.toString() : "0";
  }

  // Return the auth path for a leaf so an owner can build a witness off-chain.
  @Transaction(false)
  @Returns("string")
  async GetMerklePath(ctx: Context, leafIndex: string): Promise<string> {
    const { root, pathElements, pathIndices } = await this.computeTree(ctx, parseInt(leafIndex, 10));
    return JSON.stringify({
      root: root.toString(),
      pathElements: pathElements.map((x) => x.toString()),
      pathIndices,
    });
  }

  // ---- multi-party endorsed transfer -------------------------------------
  @Transaction()
  async InitiateTransfer(ctx: Context, parcelId: string, newCommitmentHex: string, endorsersCsv: string): Promise<void> {
    const title = await this.getJSON<Title>(ctx, TITLE(parcelId));
    if (!title) throw new Error(`no such title ${parcelId}`);
    if (title.status !== "ACTIVE") throw new Error(`title ${parcelId} not transferable (${title.status})`);
    const requiredEndorsers = endorsersCsv.split(",").map((s) => s.trim()).filter(Boolean);
    if (!requiredEndorsers.length) throw new Error("at least one endorser required");
    title.status = "PENDING_TRANSFER";
    await this.putJSON(ctx, TITLE(parcelId), title);
    const req: TransferRequest = { parcelId, newCommitment: newCommitmentHex, requiredEndorsers, endorsements: {}, status: "PENDING" };
    await this.putJSON(ctx, XFER(parcelId), req);
  }

  // The endorsing org identity is taken from the tx creator's MSP, not a param,
  // so an org cannot endorse "as" another org.
  @Transaction()
  async EndorseTransfer(ctx: Context, parcelId: string, approve: string): Promise<void> {
    const msp = ctx.clientIdentity.getMSPID();
    const req = await this.getJSON<TransferRequest>(ctx, XFER(parcelId));
    if (!req) throw new Error(`no pending transfer for ${parcelId}`);
    if (req.status !== "PENDING") throw new Error(`transfer for ${parcelId} is ${req.status}`);
    if (!req.requiredEndorsers.includes(msp)) throw new Error(`${msp} is not a required endorser`);
    const ok = approve === "true";
    req.endorsements[msp] = ok;
    if (!ok) {
      req.status = "REJECTED";
      const title = (await this.getJSON<Title>(ctx, TITLE(parcelId)))!;
      title.status = "ACTIVE";
      await this.putJSON(ctx, TITLE(parcelId), title);
    } else if (req.requiredEndorsers.every((e) => req.endorsements[e] === true)) {
      req.status = "APPROVED";
    }
    await this.putJSON(ctx, XFER(parcelId), req);
  }

  @Transaction()
  async CommitTransfer(ctx: Context, parcelId: string): Promise<void> {
    const req = await this.getJSON<TransferRequest>(ctx, XFER(parcelId));
    if (!req) throw new Error(`no transfer for ${parcelId}`);
    if (req.status !== "APPROVED") throw new Error(`endorsement policy not satisfied for ${parcelId} (status ${req.status})`);
    const title = (await this.getJSON<Title>(ctx, TITLE(parcelId)))!;
    // overwrite seller's leaf -> their old ownership proof stops verifying
    await ctx.stub.putState(LEAF(title.leafIndex), Buffer.from(BigInt(req.newCommitment).toString()));
    title.commitment = req.newCommitment;
    title.status = "ACTIVE";
    title.version += 1;
    await this.putJSON(ctx, TITLE(parcelId), title);
    req.status = "COMMITTED";
    await this.putJSON(ctx, XFER(parcelId), req);
    await this.refreshRoot(ctx);
  }

  // ---- anti-replay ZK ownership verification -----------------------------
  @Transaction()
  @Returns("string")
  async IssueChallenge(ctx: Context, parcelId: string): Promise<string> {
    if (!(await ctx.stub.getState(TITLE(parcelId)).then((b) => b && b.length))) {
      throw new Error(`no such title ${parcelId}`);
    }
    // Deterministic across endorsers: derive from tx id (unique per proposal).
    const challenge = (await H([BigInt("0x" + Buffer.from(ctx.stub.getTxID()).toString("hex").slice(0, 60))])).toString();
    await ctx.stub.putState(CHALLENGE(parcelId), Buffer.from(challenge));
    return challenge;
  }

  @Transaction(false)
  @Returns("string")
  async GetChallenge(ctx: Context, parcelId: string): Promise<string> {
    const b = await ctx.stub.getState(CHALLENGE(parcelId));
    return b && b.length ? b.toString() : "";
  }

  @Transaction()
  @Returns("boolean")
  async VerifyOwnership(ctx: Context, parcelId: string, proofJson: string): Promise<boolean> {
    const { proof, publicSignals } = JSON.parse(proofJson) as { proof: any; publicSignals: string[] };
    // publicSignals: [nullifier, root, parcelId, challenge]
    const [nullifier, root, pidSig, challengeSig] = publicSignals;

    const expectedPid = await this.parcelToField(parcelId);
    if (BigInt(pidSig) !== expectedPid) return false;

    const curRoot = await ctx.stub.getState(ROOT);
    if (BigInt(root) !== BigInt(curRoot.toString())) return false;

    const pending = await ctx.stub.getState(CHALLENGE(parcelId));
    if (!(pending && pending.length)) return false;
    if (BigInt(challengeSig) !== BigInt(pending.toString())) return false;

    if (await ctx.stub.getState(NULLIFIER(nullifier)).then((b) => b && b.length)) return false;

    const vkb = await ctx.stub.getState(VKEY);
    if (!(vkb && vkb.length)) throw new Error("vkey not initialised");
    const ok = await snarkjs.groth16.verify(JSON.parse(vkb.toString()), publicSignals, proof);
    if (!ok) return false;

    // consume: single-use
    await ctx.stub.deleteState(CHALLENGE(parcelId));
    await ctx.stub.putState(NULLIFIER(nullifier), Buffer.from("1"));
    return true;
  }

  private async parcelToField(parcelId: string): Promise<bigint> {
    let acc = 0n;
    for (const ch of parcelId) acc = acc * 256n + BigInt(ch.charCodeAt(0));
    return H([acc]);
  }
}
