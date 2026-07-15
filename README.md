# LedgerX — Permissioned Land Registry with ZK Ownership Proofs

Phase 1 vertical slice: the hard cryptographic + workflow core of an enterprise
land registry, built and verified end-to-end on a dev machine (no 10-container
Fabric network required yet).

## What actually works here (real, verified — `npm test` = 22/22 green)

1. **Privacy-preserving ownership verification (Circom + Groth16), anti-replay.**
   An owner proves *"I legitimately own parcel X"* without revealing identity,
   salt, or which registry entry is theirs. Public signals are only
   `[nullifier, merkleRoot, parcelId, challenge]`. PII never touches the chain.
   - Circuit: `circuits/ownership.circom` — Poseidon(3) commitment + depth-10
     Poseidon Merkle membership + challenge-bound nullifier.
   - `commitment = Poseidon(ownerSecret, parcelId, salt)` is the on-chain leaf.
   - `nullifier = Poseidon(ownerSecret, challenge)` binds each proof to a
     single verifier-issued challenge.

2. **Hardening (Phase 1.5):**
   - **Challenge/response:** verifier calls `issueChallenge(parcelId)`; the proof
     is cryptographically bound to that nonce.
   - **Single-use consumption:** on successful verify the challenge is burned and
     the nullifier recorded — replaying the exact proof is rejected.
   - **On-chain verification key:** VK lives in world state (`registry:vkey`),
     not read from disk at verify time — mirrors Fabric consensus.
   - **Seller-retention fix:** on transfer the seller's leaf is *overwritten*
     (not appended), so a former owner's pre-transfer proof stops verifying.

3. **Title lifecycle + multi-party endorsement state machine.**
   `contracts/registry.ts` — mint, initiate transfer, per-MSP endorse, commit.
   A transfer only commits after *all* required endorsers (e.g.
   `RegistrarMSP, NotaryMSP, TaxAuthorityMSP`) approve; a single NO reverts it.

4. **Correctness guarantees demonstrated by tests** (`test/e2e.test.ts`):
   forgery blocked, cross-parcel replay blocked, **proof replay blocked**,
   **un-issued challenge rejected**, **former owner cannot prove after sale**,
   endorsement policy enforced, rejection path restores state.

## Layout
```
circuits/ownership.circom     ZK ownership circuit (Poseidon Merkle)
contracts/crypto.ts           Poseidon Merkle tree (matches circuit hashing)
contracts/zk.ts               snarkjs prove/verify wrappers
contracts/registry.ts         Fabric-shaped registry contract + KV world-state
scripts/setup_zk.sh           Groth16 trusted setup (dev ceremony)
test/e2e.test.ts              full end-to-end proof
build/                        compiled circuit + proving/verification keys
```

## Run
```bash
npm run build:circuit   # compile circom -> r1cs/wasm
npm run setup:zk        # groth16 trusted setup (produces zkey + vkey)
npm test                # end-to-end: mint -> prove -> transfer -> verify
```

## Honest status & Phase 2 (the port to real Fabric)

This machine has 3.7 GB RAM in WSL — not enough to run a real Hyperledger Fabric
test network (orderer + peers + CAs + CouchDB + chaincode containers want
6–8 GB) without OOM thrash. So Phase 1 deliberately proves the *novel/hard*
parts (the ZK core + the endorsement/transfer logic) as working code, with the
contract written in Fabric's shape so Phase 2 is a **port, not a rewrite**.

Phase 2 checklist (needs ≥8 GB RAM or a cloud VM):
- Replace `KVStore` with Fabric `ctx.stub` (putState/getState/getStateByRange).
- Annotate `LedgerXRegistry` methods with `@Transaction` (fabric-contract-api).
- Express the 3-org rule as a Fabric **endorsement policy**
  (`AND('RegistrarMSP.peer','NotaryMSP.peer','TaxAuthorityMSP.peer')`) so it's
  enforced by consensus, not just app logic.
- Store `verification_key.json` on-chain; run `snarkjs.groth16.verify` inside
  chaincode (or a BN254 verifier) for `verifyOwnership`.
- Replace the dev trusted-setup ceremony with a proper multi-party ceremony.

## Security notes
- The trusted setup here is a single-contribution dev ceremony — **not**
  production-safe. Production requires a real multi-party ceremony.
- Owner secrets/salts are held off-chain by owners; only commitments and the
  Merkle root live on-chain.
