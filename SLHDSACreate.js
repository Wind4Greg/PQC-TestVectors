/*
SLH-DSA test vector generation for both RDFC, JCS and multiple security strengths.

FIPS 205 info:

| Name             | Private Key | Public Key | Signature Size | Sec Strength |
|------------------|-------------|------------|----------------|--------------|
|SLH-DSA-SHA2-128s |   64        | 32         | 7856           | Category 1   |
|SLH-DSA-SHA2-192s |   96        | 48         | 16224          | Category 3   |
|SLH-DSA-SHA2-256s |   128       | 64         | 29792          | Category 5   |

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
import {
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256s,
} from "@noble/post-quantum/slh-dsa.js";
import { base64url } from "multiformats/bases/base64";

let testCases = [
  {
    cryptosuite: "slhdsa128-rdfc-2024",
    sigFunc: slh_dsa_sha2_128s,
    canonScheme: "rdfc",
    hash: "sha256",
    outputDir: "./output/slhdsa128-rdfc-2024/",
    inputFile: "./input/unsigned.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysSLHDSA.json",
    keyType: "slh128s",
  },
  {
    cryptosuite: "slhdsa128-jcs-2024",
    sigFunc: slh_dsa_sha2_128s,
    canonScheme: "jcs",
    hash: "sha256",
    outputDir: "./output/slhdsa128-jcs-2024/",
    inputFile: "./input/unsigned.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysSLHDSA.json",
    keyType: "slh128s",
  },
  {
    cryptosuite: "slhdsa192-rdfc-2024",
    sigFunc: slh_dsa_sha2_192s,
    canonScheme: "rdfc",
    hash: "sha384",
    outputDir: "./output/slhdsa192-rdfc-2024/",
    inputFile: "./input/unsigned.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysSLHDSA.json",
    keyType: "slh192s",
  },
  {
    cryptosuite: "slhdsa192-jcs-2024",
    sigFunc: slh_dsa_sha2_192s,
    canonScheme: "jcs",
    hash: "sha384",
    outputDir: "./output/slhdsa192-jcs-2024/",
    inputFile: "./input/unsigned.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysSLHDSA.json",
    keyType: "slh192s",
  },
  {
    cryptosuite: "slhdsa256-rdfc-2024",
    sigFunc: slh_dsa_sha2_256s,
    canonScheme: "rdfc",
    hash: "sha512",
    outputDir: "./output/slhdsa256-rdfc-2024/",
    inputFile: "./input/unsigned.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysSLHDSA.json",
    keyType: "slh256s",
  },
  {
    cryptosuite: "slhdsa256-jcs-2024",
    sigFunc: slh_dsa_sha2_256s,
    canonScheme: "jcs",
    hash: "sha512",
    outputDir: "./output/slhdsa256-jcs-2024/",
    inputFile: "./input/unsigned.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysSLHDSA.json",
    keyType: "slh256s",
  },
];
let fileName;

for (let testCase of testCases) {
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
  let docCannon = await transform(
    document,
    testCase.canonScheme,
    testCase.hash,
  );

  // Set proof options
  let proofOptions = JSON.parse(
    await readFile(new URL(testCase.proofOptionsFile, import.meta.url)),
  );
  // Must specify cryptosuite
  proofOptions.cryptosuite = testCase.cryptosuite;
  // Must provide verification methods related to public key
  proofOptions.verificationMethod =
    "did:key:" + publicKeyMultibase + "#" + publicKeyMultibase;

  proofOptions["@context"] = document["@context"];
  // Proof Configuration
  let proofCanon = await proofConfig(
    proofOptions,
    testCase.canonScheme,
    testCase.hash,
  );

  // Hashing
  let combinedHash = hashing(docCannon, proofCanon, testCase.hash);
  // As a check against common algorithm test vector output
  // fileName = baseDir + "hashing-" + testCase.cryptosuite + ".txt";
  // writeFile(fileName, bytesToHex(combinedHash));
  // Sign
  console.log(`Signing for test case ${testCase.cryptosuite}`);
  let signature = testCase.sigFunc.sign(combinedHash, secretKey);
  // writeFile(
  //   baseDir + "sigHex" + testCase.keyType.toUpperCase() + ".txt",
  //   bytesToHex(signature),
  // );
  // console.log("Computed Signature from private key:");
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

  // Construct Signed Document
  let signedDocument = Object.assign({}, document);
  delete proofOptions["@context"];
  signedDocument.proof = proofOptions;
  signedDocument.proof.proofValue = base64url.encode(signature);

  // console.log(JSON.stringify(signedDocument, null, 2));
  writeFile(
    baseDir + "signed" + "-" + testCase.cryptosuite + ".json",
    JSON.stringify(signedDocument, null, 2),
  );
}
