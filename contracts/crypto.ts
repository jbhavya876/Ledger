import { buildPoseidon } from "circomlibjs";

// Poseidon-based Merkle tree whose hashing MUST match circuits/ownership.circom.
// Circuit hashes pairs as Poseidon(left, right); commitment = Poseidon(secret, parcelId, salt).

export type Hex = string;

let _poseidon: any = null;
export async function getPoseidon() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}

// Field element helpers ------------------------------------------------------
export async function poseidonHash(inputs: (bigint | number | string)[]): Promise<bigint> {
  const p = await getPoseidon();
  const F = p.F;
  const out = p(inputs.map((x) => BigInt(x)));
  return BigInt(F.toString(out));
}

export async function commitment(ownerSecret: bigint, parcelId: bigint, salt: bigint): Promise<bigint> {
  return poseidonHash([ownerSecret, parcelId, salt]);
}

export interface MerkleProofData {
  root: bigint;
  pathElements: bigint[];
  pathIndices: number[];
  leaf: bigint;
  leafIndex: number;
}

export class PoseidonMerkleTree {
  readonly depth: number;
  private leaves: bigint[];
  private zeros: bigint[] = [];
  layers: bigint[][] = [];

  private constructor(depth: number) {
    this.depth = depth;
    this.leaves = [];
  }

  static async create(depth: number, leaves: bigint[] = []): Promise<PoseidonMerkleTree> {
    const t = new PoseidonMerkleTree(depth);
    // precompute zero values for empty subtrees
    let z = 0n;
    t.zeros.push(z);
    for (let i = 0; i < depth; i++) {
      z = await poseidonHash([z, z]);
      t.zeros.push(z);
    }
    for (const l of leaves) t.leaves.push(l);
    await t.rebuild();
    return t;
  }

  async insert(leaf: bigint): Promise<number> {
    const idx = this.leaves.length;
    this.leaves.push(leaf);
    await this.rebuild();
    return idx;
  }

  // Overwrite an existing leaf (used on title transfer so the previous owner's
  // commitment ceases to be a member of the tree -> old proofs stop verifying).
  async updateLeaf(index: number, leaf: bigint): Promise<void> {
    if (index < 0 || index >= this.leaves.length) throw new Error(`leaf index ${index} out of range`);
    this.leaves[index] = leaf;
    await this.rebuild();
  }

  private async rebuild(): Promise<void> {
    this.layers = [];
    let cur = this.leaves.slice();
    this.layers.push(cur);
    for (let d = 0; d < this.depth; d++) {
      const next: bigint[] = [];
      for (let i = 0; i < cur.length; i += 2) {
        const left = cur[i];
        const right = i + 1 < cur.length ? cur[i + 1] : this.zeros[d];
        next.push(await poseidonHash([left, right]));
      }
      if (next.length === 0) next.push(this.zeros[d + 1]);
      this.layers.push(next);
      cur = next;
    }
  }

  get root(): bigint {
    const top = this.layers[this.depth];
    return top && top.length ? top[0] : this.zeros[this.depth];
  }

  proof(leafIndex: number): MerkleProofData {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`leafIndex ${leafIndex} out of range`);
    }
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let idx = leafIndex;
    for (let d = 0; d < this.depth; d++) {
      const layer = this.layers[d];
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      const sibling = siblingIdx < layer.length ? layer[siblingIdx] : this.zeros[d];
      pathElements.push(sibling);
      pathIndices.push(isRight ? 1 : 0);
      idx = Math.floor(idx / 2);
    }
    return { root: this.root, pathElements, pathIndices, leaf: this.leaves[leafIndex], leafIndex };
  }
}
