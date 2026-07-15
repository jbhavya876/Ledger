#!/usr/bin/env bash
# Groth16 trusted setup for the ownership circuit.
# NOTE: uses a local dev ceremony (single contribution). For production a
# proper multi-party ceremony is required.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
cd build

POWER=13   # 2^13 = 8192 constraints capacity (circuit uses ~5.8k)

if [ ! -f pot${POWER}_final.ptau ]; then
  echo ">> powers of tau (phase 1)"
  snarkjs powersoftau new bn128 ${POWER} pot_0000.ptau -v
  snarkjs powersoftau contribute pot_0000.ptau pot_0001.ptau \
     --name="ledgerx dev contribution" -v -e="$(head -c 64 /dev/urandom | xxd -p | tr -d '\n')"
  echo ">> prepare phase 2"
  snarkjs powersoftau prepare phase2 pot_0001.ptau pot${POWER}_final.ptau -v
fi

echo ">> groth16 setup (phase 2)"
snarkjs groth16 setup ownership.r1cs pot${POWER}_final.ptau ownership_0000.zkey
snarkjs zkey contribute ownership_0000.zkey ownership_final.zkey \
   --name="ledgerx key contribution" -v -e="$(head -c 64 /dev/urandom | xxd -p | tr -d '\n')"
snarkjs zkey export verificationkey ownership_final.zkey verification_key.json

echo ">> DONE. artifacts:"
ls -la ownership_final.zkey verification_key.json ownership_js/ownership.wasm
