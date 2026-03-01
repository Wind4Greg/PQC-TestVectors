/*
    Steps to recreate "ecdsa-rdfc-2019" and "ecdsa-jcs-2019" test vectors
    using general processing functions.
*/

import { mkdir, readFile, writeFile } from "fs/promises";
import { base58btc } from "multiformats/bases/base58";
import { p256 as P256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as utils from "@noble/hashes/utils.js";
const { bytesToHex, hexToBytes } = utils;
import { proofConfig, transform, hashing } from "./DIUtils.js";

// General scheme parameters
const hash = "sha256";

const tests = [
  {
    outputDir: "./output/ecdsa-rdfc-2019-p256/alumni/",
    inputFile: "./input/unsigned.json",
    proofOptionsFile: "./input/proofOptions.json",
    cryptosuite: "ecdsa-rdfc-2019",
    canonScheme: "rdfc",
  },
  {
    outputDir: "./output/ecdsa-jcs-2019-p256/alumni/",
    inputFile: "./input/unsigned.json",
    proofOptionsFile: "./input/proofOptions.json",
    cryptosuite: "ecdsa-jcs-2019",
    canonScheme: "jcs",
  },
];

for (let testParams of tests) {
  // Create output directory for the results
  const baseDir = testParams.outputDir;
  let status = await mkdir(baseDir, { recursive: true });

  const keyPair = {
    publicKeyMultibase: "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
  };

  let privateKey = hexToBytes(
    "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
  );
  let publicKey = P256.getPublicKey(privateKey);

  // Read input document from a file or just specify it right here.
  let document = JSON.parse(
    await readFile(new URL(testParams.inputFile, import.meta.url)),
  );

  // Signed Document Creation Steps:

  // Transform the document
  let docCannon = await transform(document, testParams.canonScheme);
  writeFile(baseDir + "transformDocECDSAP256.txt", docCannon);

  // Set proof options
  let proofOptions = JSON.parse(
    await readFile(new URL(testParams.proofOptionsFile, import.meta.url)),
  );
  // Must specify cryptosuite
  proofOptions.cryptosuite = testParams.cryptosuite;
  // Must provide verification methods related to public key
  proofOptions.verificationMethod =
    "did:key:" + keyPair.publicKeyMultibase + "#" + keyPair.publicKeyMultibase;
  proofOptions["@context"] = document["@context"];
  // Proof Configuration
  let proofCanon = await proofConfig(proofOptions, testParams.canonScheme);
  console.log("Proof Configuration Canonized:");
  console.log(proofCanon);
  writeFile(baseDir + "proofCanonECDSAP256.txt", proofCanon);

  // Hashing
  let combinedHash = hashing(docCannon, proofCanon, hash);
  writeFile(baseDir + "combinedHashECDSAP256.txt", bytesToHex(combinedHash));

  // Sign
  let msgHash = sha256(combinedHash); // Hash is done outside of the algorithm in noble/curve case.
  let signature = P256.sign(msgHash, privateKey, {
    prehash: false,
    lowS: false,
  });
  console.log("P256 based signature:");
  console.log(signature);
  writeFile(baseDir + "sigHexECDSAP256.txt", bytesToHex(signature));
  console.log("Computed Signature from private key:");
  console.log(base58btc.encode(signature));
  writeFile(baseDir + "sigBTC58ECDSAP256.txt", base58btc.encode(signature));

  // Verify (just to see we have a good private/public pair)
  let pbk = base58btc.decode(keyPair.publicKeyMultibase);
  pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
  console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
  let result = P256.verify(signature, msgHash, pbk, {
    prehash: false,
    lowS: false,
  });
  console.log(`Signature verified: ${result}`);

  // Construct Signed Document
  let signedDocument = Object.assign({}, document);
  delete proofOptions["@context"];
  signedDocument.proof = proofOptions;
  signedDocument.proof.proofValue = base58btc.encode(signature);

  console.log(JSON.stringify(signedDocument, null, 2));
  writeFile(
    baseDir + "signedECDSAP256.json",
    JSON.stringify(signedDocument, null, 2),
  );
}
