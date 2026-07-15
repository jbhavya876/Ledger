// Compute commitment = Poseidon(ownerSecret, parcelIdField, salt) for minting.
// Usage: tsx scripts/gen_commitment.ts <parcelId> <ownerSecret> <salt>
import { buildPoseidon } from "circomlibjs";

async function main() {
  const [parcelId, ownerSecret, salt] = process.argv.slice(2);
  const p = await buildPoseidon();
  const F = p.F;
  const H = (xs: bigint[]) => BigInt(F.toString(p(xs)));
  let acc = 0n;
  for (const ch of parcelId) acc = acc * 256n + BigInt(ch.charCodeAt(0));
  const parcelField = H([acc]);
  const commitment = H([BigInt(ownerSecret), parcelField, BigInt(salt)]);
  process.stdout.write(commitment.toString());
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
