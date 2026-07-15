// CCAAS entrypoint: run the contract-api chaincode as a gRPC service.
// Mirrors fabric-shim's Bootstrap.register(..., serverMode=true): wrap the
// contract(s) with ChaincodeFromContract, then hand that to shim.server().
import * as shim from "fabric-shim";
import { LedgerXContract } from "./ledgerx";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const ChaincodeFromContract = require("fabric-shim/lib/contract-spi/chaincodefromcontract");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { JSONSerializer } = require("fabric-contract-api");

const serializers = {
  transaction: "jsonSerializer",
  serializers: { jsonSerializer: JSONSerializer },
};

const chaincode = new ChaincodeFromContract(
  [LedgerXContract],
  serializers,
  {},                 // fileMetadata
  "ledgerx",
  "1.0"
);

const server = (shim as any).server(chaincode, {
  ccid: process.env.CHAINCODE_ID as string,
  address: process.env.CHAINCODE_SERVER_ADDRESS as string,
});

server.start()
  .then(() => console.log(`LedgerX chaincode server on ${process.env.CHAINCODE_SERVER_ADDRESS}`))
  .catch((e: unknown) => { console.error(e); process.exit(1); });
