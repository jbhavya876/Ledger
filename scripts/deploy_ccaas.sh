#!/usr/bin/env bash
# Phase 2 end-to-end on real Fabric (2-org, CCAAS deploy).
# Assumes: network up + mychannel created; ledgerx-ccaas:1.0 image built.
set -euo pipefail

TN=~/fabric-samples/test-network
CC=~/ledgerx/chaincode-ts
export PATH=$TN/../bin:$PATH
export FABRIC_CFG_PATH=$TN/../config
export CONTAINER_CLI_COMPOSE="docker compose"
CHANNEL=mychannel
CCNAME=ledgerx
SEQ=1

cd "$TN"

# --- org env helpers ---
setOrg1() {
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID=Org1MSP
  export CORE_PEER_TLS_ROOTCERT_FILE=$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
  export CORE_PEER_ADDRESS=localhost:7051
}
setOrg2() {
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID=Org2MSP
  export CORE_PEER_TLS_ROOTCERT_FILE=$TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=$TN/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
  export CORE_PEER_ADDRESS=localhost:9051
}
ORDERER_CA=$TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
ORG1_CA=$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
ORG2_CA=$TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt

peerBoth() { echo "--peerAddresses localhost:7051 --tlsRootCertFiles $ORG1_CA --peerAddresses localhost:9051 --tlsRootCertFiles $ORG2_CA"; }

echo "===================== [1] PACKAGE (ccaas) ====================="
cd "$CC/ccaas-package"
tar czf code.tar.gz connection.json
tar czf ../ledgerx-ccaas.tgz metadata.json code.tar.gz
cd "$TN"
CC_PKG=$CC/ledgerx-ccaas.tgz
ls -la "$CC_PKG"

echo "===================== [2] INSTALL on both peers ====================="
setOrg1; peer lifecycle chaincode install "$CC_PKG"
setOrg2; peer lifecycle chaincode install "$CC_PKG"

setOrg1
PKGID=$(peer lifecycle chaincode queryinstalled --output json | jq -r ".installed_chaincodes[] | select(.label==\"ledgerx_1.0\") | .package_id")
echo "PACKAGE_ID=$PKGID"

echo "===================== [3] START chaincode container (CCAAS) ====================="
docker rm -f ledgerx-ccaas 2>/dev/null || true
docker run -d --name ledgerx-ccaas --network fabric_test \
  -e CHAINCODE_ID="$PKGID" \
  -e CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999 \
  ledgerx-ccaas:1.0
sleep 4
docker logs ledgerx-ccaas 2>&1 | tail -5

echo "===================== [4] APPROVE from both orgs (AND policy) ====================="
POLICY="AND('Org1MSP.peer','Org2MSP.peer')"
for org in 1 2; do
  eval "setOrg$org"
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --channelID $CHANNEL --name $CCNAME --version 1.0 --package-id "$PKGID" \
    --sequence $SEQ --signature-policy "$POLICY" --tls --cafile "$ORDERER_CA"
done

echo "===================== [5] CHECK COMMIT READINESS ====================="
setOrg1
peer lifecycle chaincode checkcommitreadiness --channelID $CHANNEL --name $CCNAME --version 1.0 \
  --sequence $SEQ --signature-policy "$POLICY" --tls --cafile "$ORDERER_CA" --output json

echo "===================== [6] COMMIT ====================="
setOrg1
peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --channelID $CHANNEL --name $CCNAME --version 1.0 --sequence $SEQ \
  --signature-policy "$POLICY" --tls --cafile "$ORDERER_CA" $(peerBoth)

peer lifecycle chaincode querycommitted --channelID $CHANNEL --name $CCNAME --tls --cafile "$ORDERER_CA"
echo "DEPLOY OK"
