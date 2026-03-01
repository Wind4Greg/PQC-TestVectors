/*
  Example verifying ECDSA test vectors using general processing functions.
*/
import { readFile } from "fs/promises";
import { base58btc } from "multiformats/bases/base58";
import { p256 as P256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as utils from "@noble/hashes/utils.js";
const { bytesToHex } = utils;
import { proofConfig, transform, hashing } from "./DIUtils.js";

const hash = "sha256";

const tests = [
  {
    baseDir: "./output/ecdsa-rdfc-2019-p256/alumni/",
    canonScheme: "rdfc",
  },
  {
    baseDir: "./output/ecdsa-jcs-2019-p256/alumni/",
    canonScheme: "jcs",
  },
];

for (let testParams of tests) {
  // Read signed input document from a file or just specify it right here.
  const signedDocument = JSON.parse(
    await readFile(
      new URL(testParams.baseDir + "signedECDSAP256.json", import.meta.url),
    ),
  );

  // Document without proof
  let document = Object.assign({}, signedDocument);
  delete document.proof;
  // console.log(document);

  // Canonize the document
  let cannon = await transform(document, testParams.canonScheme);

  // Set proof options per draft
  let proofOptions = {};
  proofOptions.type = signedDocument.proof.type;
  proofOptions.cryptosuite = signedDocument.proof.cryptosuite;
  proofOptions.created = signedDocument.proof.created;
  proofOptions.verificationMethod = signedDocument.proof.verificationMethod;
  proofOptions.proofPurpose = signedDocument.proof.proofPurpose;
  proofOptions["@context"] = signedDocument["@context"]; // Missing from draft!!!

  // canonize the proof config
  let proofCanon = await proofConfig(proofOptions, testParams.canonScheme);
  // console.log("Proof Configuration Canonized:");
  // console.log(proofCanon);

  // Hashing
  let combinedHash = hashing(cannon, proofCanon, hash);

  // Get public key
  let encodedPbk = signedDocument.proof.verificationMethod.split("#")[1];
  let pbk = base58btc.decode(encodedPbk);
  pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
  console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);

  // Verify
  let msgHash = sha256(combinedHash); // Hash is done outside of the algorithm in noble/curve case.
  let signature = base58btc.decode(signedDocument.proof.proofValue);
  let result = P256.verify(signature, msgHash, pbk, {
    prehash: false,
    lowS: false,
  });
  console.log(`File: ${testParams.baseDir + "signedECDSAP256.json"}:`);
  console.log(`Signature verified: ${result}`);
}
