pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

// Proves, in zero knowledge, that the prover knows the secret pre-image of a
// title commitment that is a member of the registry's Merkle tree (root is
// public), AND that the committed parcelId equals the public parcelId being
// queried -- WITHOUT revealing the owner identity, the salt, or the tree path.
//
// commitment = Poseidon(ownerSecret, parcelId, salt)
//
// HARDENING (anti-replay):
//   * `challenge` is a public verifier-issued nonce; the proof is only valid
//     against the exact challenge it was generated for.
//   * `nullifier = Poseidon(ownerSecret, challenge)` is emitted publicly so the
//     registry can mark a (proof-session) as consumed. Replaying the same proof
//     re-presents the same nullifier -> rejected. A new challenge forces a new
//     proof, which the attacker cannot produce without ownerSecret.

template MerkleProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth]; // 0 = leaf is left, 1 = leaf is right
    signal output root;

    component hashers[depth];
    component mux[depth];

    signal cur[depth + 1];
    cur[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== cur[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== cur[i];
        mux[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        cur[i + 1] <== hashers[i].out;
    }

    root <== cur[depth];
}

template Ownership(depth) {
    // ---- Private inputs (never revealed) ----
    signal input ownerSecret;
    signal input salt;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // ---- Public inputs ----
    signal input root;        // registry Merkle root (on-chain)
    signal input parcelId;    // parcel whose ownership is claimed
    signal input challenge;   // verifier-issued nonce (anti-replay)

    // ---- Public output ----
    signal output nullifier;  // Poseidon(ownerSecret, challenge)

    // 1. Recompute the commitment leaf
    component commit = Poseidon(3);
    commit.inputs[0] <== ownerSecret;
    commit.inputs[1] <== parcelId;
    commit.inputs[2] <== salt;

    // 2. Prove membership in the tree rooted at `root`
    component mp = MerkleProof(depth);
    mp.leaf <== commit.out;
    for (var i = 0; i < depth; i++) {
        mp.pathElements[i] <== pathElements[i];
        mp.pathIndices[i] <== pathIndices[i];
    }
    mp.root === root;

    // 3. Bind proof to the challenge via a nullifier derived from the secret.
    //    `challenge` is a declared public input, so it is committed into the
    //    proof even though only the nullifier is an explicit output.
    component nf = Poseidon(2);
    nf.inputs[0] <== ownerSecret;
    nf.inputs[1] <== challenge;
    nullifier <== nf.out;
}

component main {public [root, parcelId, challenge]} = Ownership(10);
