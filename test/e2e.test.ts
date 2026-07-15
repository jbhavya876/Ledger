import { LedgerXRegistry, KVStore, parcelToField } from "../contracts/registry";
import { PoseidonMerkleTree, commitment } from "../contracts/crypto";
import { buildWitness, proveOwnership, nullifierOf, expectedNullifier } from "../contracts/zk";

const ALICE_SECRET = 111111111111n;
const BOB_SECRET   = 222222222222n;
const MALLORY_SECRET = 999999999999n;

let pass = 0, fail = 0;
function check(name: string, cond: boolean) {
  if (cond) { console.log(`  \u2713 ${name}`); pass++; }
  else { console.log(`  \u2717 ${name}`); fail++; }
}

async function main() {
  console.log("=== LedgerX end-to-end (HARDENED) ===\n");
  const db = new KVStore();
  const reg = new LedgerXRegistry(db, 10);
  await reg.init();

  // ---- 1. MINT ----
  console.log("[1] Mint titles (commitments only, no PII on-chain)");
  const parcelA = "PARCEL-DELHI-001";
  const parcelB = "PARCEL-MUMBAI-002";
  const pidA = await parcelToField(parcelA);
  const pidB = await parcelToField(parcelB);
  const saltA = 424242n, saltB = 838383n;
  const commitA = await commitment(ALICE_SECRET, pidA, saltA);
  const commitB = await commitment(BOB_SECRET, pidB, saltB);
  const tA = await reg.mintTitle(parcelA, commitA.toString());
  await reg.mintTitle(parcelB, commitB.toString());
  check("two titles minted", (await reg.getTitle(parcelA)) != null && (await reg.getTitle(parcelB)) != null);
  check("on-chain title has NO owner PII", !JSON.stringify(tA).toLowerCase().includes("alice"));

  // ---- 1b. VK on-chain ----
  console.log("\n[1b] Verification key stored on-chain (world state)");
  const vk = await reg.getVerificationKey();
  check("vkey readable from state, protocol=groth16", vk && vk.protocol === "groth16");

  // ---- 2. CHALLENGE-BOUND ZK PROOF ----
  console.log("\n[2] Alice: verifier issues challenge, Alice proves for THAT challenge");
  const chA = await reg.issueChallenge(parcelA);
  const wA = await buildWitness(reg.merkleTree, tA.leafIndex, ALICE_SECRET, pidA, saltA, chA);
  const proofA = await proveOwnership(wA);
  check("public signals = [nullifier, root, parcelId, challenge]", proofA.publicSignals.length === 4);
  check("nullifier == Poseidon(secret, challenge)", nullifierOf(proofA) === await expectedNullifier(ALICE_SECRET, chA));
  check("valid challenge-bound proof verifies", await reg.verifyOwnership(parcelA, proofA));

  // ---- 3. REPLAY ATTACK ----
  console.log("\n[3] Replay: attacker re-submits Alice's exact proof");
  check("replay rejected (challenge consumed + nullifier seen)", !(await reg.verifyOwnership(parcelA, proofA)));

  // ---- 4. STALE-CHALLENGE / no fresh challenge ----
  console.log("\n[4] Proof with no freshly-issued challenge is rejected");
  // a new proof against a random challenge the registry never issued
  const bogus = 123456789n;
  const wStale = await buildWitness(reg.merkleTree, tA.leafIndex, ALICE_SECRET, pidA, saltA, bogus);
  const proofStale = await proveOwnership(wStale);
  check("proof for un-issued challenge rejected", !(await reg.verifyOwnership(parcelA, proofStale)));

  // ---- 5. FRESH challenge required each time ----
  console.log("\n[5] A new challenge yields a fresh, verifiable proof");
  const chA2 = await reg.issueChallenge(parcelA);
  const wA2 = await buildWitness(reg.merkleTree, tA.leafIndex, ALICE_SECRET, pidA, saltA, chA2);
  const proofA2 = await proveOwnership(wA2);
  check("new challenge -> new nullifier", nullifierOf(proofA2) !== nullifierOf(proofA));
  check("fresh proof verifies", await reg.verifyOwnership(parcelA, proofA2));

  // ---- 6. FORGERY ----
  console.log("\n[6] Mallory cannot forge ownership");
  let malloryFailed = false;
  try { await buildWitness(reg.merkleTree, tA.leafIndex, MALLORY_SECRET, pidA, saltA, chA2); }
  catch { malloryFailed = true; }
  check("Mallory cannot build a witness (commitment mismatch)", malloryFailed);

  // ---- 7. CROSS-PARCEL replay ----
  console.log("\n[7] Alice's parcelA proof rejected against parcelB");
  const chB = await reg.issueChallenge(parcelB);
  void chB;
  check("cross-parcel proof rejected", !(await reg.verifyOwnership(parcelB, proofA2)));

  // ---- 8. MULTI-PARTY ENDORSED TRANSFER ----
  console.log("\n[8] Transfer parcelA Alice -> Carol w/ 3-org endorsement");
  const CAROL_SECRET = 333333333333n, saltC = 555555n;
  const commitCarol = await commitment(CAROL_SECRET, pidA, saltC);
  const endorsers = ["RegistrarMSP", "NotaryMSP", "TaxAuthorityMSP"];
  await reg.initiateTransfer(parcelA, commitCarol.toString(), endorsers);
  check("title PENDING_TRANSFER", (await reg.getTitle(parcelA))!.status === "PENDING_TRANSFER");
  let r = await reg.endorseTransfer(parcelA, "RegistrarMSP", true);
  check("not committable at 1/3", r.status === "PENDING");
  await reg.endorseTransfer(parcelA, "NotaryMSP", true);
  r = await reg.endorseTransfer(parcelA, "TaxAuthorityMSP", true);
  check("APPROVED at 3/3", r.status === "APPROVED");
  const updated = await reg.commitTransfer(parcelA);
  check("owned by Carol's commitment", updated.commitment === commitCarol.toString());
  check("version incremented", updated.version === 2);

  // ---- 9. Ownership shifts + stale root ----
  console.log("\n[9] Post-transfer: Carol proves, Alice's old-root proof fails");
  const chC = await reg.issueChallenge(parcelA);
  const wCarol = await buildWitness(reg.merkleTree, updated.leafIndex, CAROL_SECRET, pidA, saltC, chC);
  const proofCarol = await proveOwnership(wCarol);
  check("Carol's proof (new root) verifies", await reg.verifyOwnership(parcelA, proofCarol));
  const chC2 = await reg.issueChallenge(parcelA);
  let aliceCannotProve = false;
  try {
    const wAliceOld = await buildWitness(reg.merkleTree, tA.leafIndex, ALICE_SECRET, pidA, saltA, chC2);
    const proofAliceOld = await proveOwnership(wAliceOld);
    aliceCannotProve = !(await reg.verifyOwnership(parcelA, proofAliceOld));
  } catch {
    // seller's leaf was overwritten -> she can't even build a witness
    aliceCannotProve = true;
  }
  check("Alice (former owner) can no longer prove ownership", aliceCannotProve);

  // ---- 10. Rejection path ----
  console.log("\n[10] Rejection path: a single NO reverts the transfer");
  const commitX = await commitment(777n, pidB, 1n);
  await reg.initiateTransfer(parcelB, commitX.toString(), endorsers);
  await reg.endorseTransfer(parcelB, "RegistrarMSP", true);
  const rej = await reg.endorseTransfer(parcelB, "NotaryMSP", false);
  check("REJECTED on NO vote", rej.status === "REJECTED");
  check("title restored ACTIVE", (await reg.getTitle(parcelB))!.status === "ACTIVE");
  let blocked = false;
  try { await reg.commitTransfer(parcelB); } catch { blocked = true; }
  check("cannot commit rejected transfer", blocked);

  console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
