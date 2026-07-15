#!/usr/bin/env bash
# Phase 2 functional test on real Fabric: mint -> ZK ownership verify (real
# Groth16, verified inside chaincode) -> multi-org endorsement.
set -uo pipefail

TN=~/fabric-samples/test-network
LX=~/ledgerx
export PATH=$TN/../bin:$PATH
export FABRIC_CFG_PATH=$TN/../config
CHANNEL=mychannel; CCNAME=ledgerx
cd "$TN"

ORDERER_CA=$TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
ORG1_CA=$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
ORG2_CA=$TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
setOrg1() { export CORE_PEER_TLS_ENABLED=true CORE_PEER_LOCALMSPID=Org1MSP CORE_PEER_TLS_ROOTCERT_FILE=$ORG1_CA CORE_PEER_MSPCONFIGPATH=$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp CORE_PEER_ADDRESS=localhost:7051; }
BOTH="--peerAddresses localhost:7051 --tlsRootCertFiles $ORG1_CA --peerAddresses localhost:9051 --tlsRootCertFiles $ORG2_CA"
ORD="-o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile $ORDERER_CA"
inv() { setOrg1; peer chaincode invoke $ORD -C $CHANNEL -n $CCNAME $BOTH -c "$1" --waitForEvent 2>&1; }
qry() { setOrg1; peer chaincode query -C $CHANNEL -n $CCNAME -c "$1" 2>&1; }

PASS=0; FAIL=0
ckc() { if echo "$2" | grep -q "$3"; then echo "  PASS: $1"; PASS=$((PASS+1)); else echo "  FAIL: $1"; echo "        got: $2"; FAIL=$((FAIL+1)); fi; }

echo "===== [1] InitLedger: store verification key on-chain ====="
VK=$(jq -c . "$LX/build/verification_key.json")
R=$(inv "{\"function\":\"InitLedger\",\"Args\":[$(jq -Rs . <<<"$VK")]}")
ckc "InitLedger committed" "$R" "status:200"

echo "===== [2] MintTitle: commitment only, no PII ====="
PARCEL="PARCEL-DELHI-$(date +%s)"; ALICE=111111111111; SALTA=424242
COMMITA=$(cd $LX && npx tsx scripts/gen_commitment.ts "$PARCEL" "$ALICE" "$SALTA")
R=$(inv "{\"function\":\"MintTitle\",\"Args\":[\"$PARCEL\",\"$COMMITA\"]}")
ckc "MintTitle committed" "$R" "status:200"
sleep 2
T=$(qry "{\"function\":\"ReadTitle\",\"Args\":[\"$PARCEL\"]}")
echo "  on-chain title: $T"
ckc "title ACTIVE"      "$T" "ACTIVE"
ckc "commitment stored" "$T" "$COMMITA"

echo "===== [3] GetMerklePath + IssueChallenge ====="
LEAFIDX=$(echo "$T" | jq -r .leafIndex)
PATHJSON=$(qry "{\"function\":\"GetMerklePath\",\"Args\":[\"$LEAFIDX\"]}")
ckc "merkle path returned" "$PATHJSON" "root"
inv "{\"function\":\"IssueChallenge\",\"Args\":[\"$PARCEL\"]}" >/dev/null
sleep 2
CH=$(qry "{\"function\":\"GetChallenge\",\"Args\":[\"$PARCEL\"]}")
echo "  challenge=$CH"
ckc "challenge issued" "$CH" "[0-9]"

echo "===== [4] Generate REAL Groth16 proof off-chain (owner side) ====="
cd $LX && npx tsx scripts/gen_proof.ts "$PARCEL" "$ALICE" "$SALTA" "$LEAFIDX" "$CH" "$PATHJSON" > /tmp/lx_proof.json 2>/tmp/lx_proof.err
if [ -s /tmp/lx_proof.json ]; then echo "  PASS: proof generated ($(wc -c </tmp/lx_proof.json) bytes)"; PASS=$((PASS+1)); else echo "  FAIL: proof gen"; cat /tmp/lx_proof.err; FAIL=$((FAIL+1)); fi
cd "$TN"
PROOF=$(cat /tmp/lx_proof.json)

echo "===== [5] VerifyOwnership through peers (ZK verified inside chaincode, AND endorsement) ====="
R=$(inv "{\"function\":\"VerifyOwnership\",\"Args\":[\"$PARCEL\",$(jq -Rs . <<<"$PROOF")]}")
echo "  $(echo "$R" | grep -oE 'status:[0-9]+|payload:\"[^\"]*\"|Error.*' | head -2)"
ckc "ownership verified on-chain (status 200)" "$R" "status:200"
ckc "verify returned true" "$R" "true"

echo "===== [6] Replay rejected (challenge consumed) ====="
R=$(inv "{\"function\":\"VerifyOwnership\",\"Args\":[\"$PARCEL\",$(jq -Rs . <<<"$PROOF")]}")
ckc "replay rejected" "$R" "false"

echo ""
echo "===== RESULT: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
