/*
FALCON test vector generation for both RDFC, JCS and multiple security strengths.

| Name 	      | Security   |	Private Key |	Public Key | Signature |
| FALCON-512  |	Category 1 |  1281        |	897 	     | 666       |
| FALCON-1024 |	Category 5 |	2305        |	1793       | 1280      |
FIPS 204 info:

Hash collision resistance strength:

| Sec Strength | Hash Function |
|--------------|---------------|
| Cat 1 or 2   | SHA-256       |
| Cat 3 or 4   | SHA-384       |
| Cat 5        | SHA-512       |

*/

import { mkdir, readFile, writeFile } from "fs/promises";
import * as utils from "@noble/hashes/utils.js";
const { bytesToHex, hexToBytes } = utils;
import { proofConfig, transform, hashing } from "./DIUtils.js";
import { falcon512, falcon1024 } from  "@noble/post-quantum/falcon.js";
import { base64url } from "multiformats/bases/base64";

let testCases = [
  {
    cryptosuite: "falcon512-rdfc-2024",
    sigFunc: falcon512,
    canonScheme: "rdfc",
    hash: "sha256",
    outputDir: "./output/falcon512-rdfc-2024/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysFALCON.json",
    keyType: "falcon512",
  },
  {
    cryptosuite: "falcon512-jcs-2024",
    sigFunc: falcon512,
    canonScheme: "jcs",
    hash: "sha256",
    outputDir: "./output/falcon512-jcs-2024/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysFALCON.json",
    keyType: "falcon512",
  },
  {
    cryptosuite: "falcon1024-rdfc-2024",
    sigFunc: falcon1024,
    canonScheme: "rdfc",
    hash: "sha512",
    outputDir: "./output/falcon1024-rdfc-2024/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysFALCON.json",
    keyType: "falcon1024",
  },
  {
    cryptosuite: "falcon1024-jcs-2024",
    sigFunc: falcon1024,
    canonScheme: "jcs",
    hash: "sha512",
    outputDir: "./output/falcon1024-jcs-2024/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysFALCON.json",
    keyType: "falcon1024",
  },
];

for (let testCase of testCases) {
  let fileName;
  // Create output directory for the results
  const baseDir = testCase.outputDir;
  let status = await mkdir(baseDir, { recursive: true });

  let allKeys = JSON.parse(
    await readFile(new URL(testCase.keyFile, import.meta.url)),
  );
  const publicKeyMultibase = allKeys[testCase.keyType].publicKeyMultibase;
  let secretKey = hexToBytes(allKeys[testCase.keyType].secretKeyHex);
  let publicKey = hexToBytes(allKeys[testCase.keyType].publicKeyHex);

  // Read input document from a file or just specify it right here.
  let document = JSON.parse(
    await readFile(new URL(testCase.inputFile, import.meta.url)),
  );

  // Signed Document Creation Steps:

  // Transform the document
  let docCanon = await transform(document, testCase.canonScheme, testCase.hash);
  // Set proof options
  let proofOptions = JSON.parse(
    await readFile(new URL(testCase.proofOptionsFile, import.meta.url)),
  );
  // Must specify cryptosuite
  proofOptions.cryptosuite = testCase.cryptosuite;
  // Must provide verification methods related to public key
  proofOptions.verificationMethod =
    "did:key:" + publicKeyMultibase;

  proofOptions["@context"] = document["@context"];
  // Proof Configuration
  let proofCanon = await proofConfig(
    proofOptions,
    testCase.canonScheme,
    testCase.hash,
  );

  // Hashing
  let combinedHash = hashing(docCanon, proofCanon, testCase.hash);
  // As a check against common algorithm test vector output
  // fileName = baseDir + "hashing-" + testCase.cryptosuite + ".txt";
  // writeFile(fileName, bytesToHex(combinedHash));

  // Sign
  let signature = testCase.sigFunc.sign(combinedHash, secretKey);
  // writeFile(
  //   baseDir + "sigHex" + testCase.keyType.toUpperCase() + ".txt",
  //   bytesToHex(signature),
  // );
  // writeFile(
  //   baseDir + "sigBase64url" + testCase.keyType.toUpperCase() + ".txt",
  //   base64url.encode(signature),
  // );
  // Verify (just to see we have a good private/public pair)
  let pbk = base64url.decode(publicKeyMultibase);
  pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
  // console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
  let result = testCase.sigFunc.verify(signature, combinedHash, pbk);
  console.log(`Signature verified: ${result}`);
  console.log(`Signature size: ${signature.length}`);

  // Construct Signed Document
  let signedDocument = Object.assign({}, document);
  delete proofOptions["@context"];
  signedDocument.proof = proofOptions;
  signedDocument.proof.proofValue = base64url.encode(signature);
  writeFile(
    baseDir + "signed" + "-" + testCase.cryptosuite + ".json",
    JSON.stringify(signedDocument, null, 2),
  );
}
