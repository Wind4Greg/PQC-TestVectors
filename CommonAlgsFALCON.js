/*
Test vector generation for common algorithms: Proof Configuration, Transform,
and Hashing.

Since the cryptosuite name appears in the `proof options` the Proof Options and
Hashing algorithms outputs are dependent on this.

*/

import { mkdir, readFile, writeFile } from "fs/promises";
import * as utils from "@noble/hashes/utils.js";
const { bytesToHex, hexToBytes } = utils;
import { proofConfig, transform, hashing } from "./DIUtils.js";

const commonAlgDir = "./output/commonAlgs/";
const allHashes = {};

let testCases = [
  {
    cryptosuite: "falcon512-rdfc-2024",
    canonScheme: "rdfc",
    hash: "sha256",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysFALCON.json",
    keyType: "falcon512",
  },
  {
    cryptosuite: "falcon512-jcs-2024",
    canonScheme: "jcs",
    hash: "sha256",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysFALCON.json",
    keyType: "falcon512",
  },
  {
    cryptosuite: "falcon1024-rdfc-2024",
    canonScheme: "rdfc",
    hash: "sha512",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysFALCON.json",
    keyType: "falcon1024",
  },
  {
    cryptosuite: "falcon1024-jcs-2024",
    canonScheme: "jcs",
    hash: "sha512",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysFALCON.json",
    keyType: "falcon1024",
  },
];

for (let testCase of testCases) {
  // Create output directory for the results
  let status = await mkdir(commonAlgDir, { recursive: true });

  let allKeys = JSON.parse(
    await readFile(new URL(testCase.keyFile, import.meta.url)),
  );
  // console.log(allKeys);
  const publicKeyMultibase = allKeys[testCase.keyType].publicKeyMultibase;

  // Read input document from a file or just specify it right here.
  let document = JSON.parse(
    await readFile(new URL(testCase.inputFile, import.meta.url)),
  );

  // Common Algorithms

  // Transform the document
  let docCanon = await transform(document, testCase.canonScheme, testCase.hash);
  // write to commonAlg output
  let fileName =
    commonAlgDir +
    "transform-" +
    testCase.canonScheme +
    "-" +
    testCase.hash +
    ".txt";
  writeFile(fileName, docCanon);
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
  // write to commonAlg output
  fileName = commonAlgDir + "proofConfig-" + testCase.cryptosuite + ".txt";
  writeFile(fileName, proofCanon);

  // Hashing
  let combinedHash = hashing(docCanon, proofCanon, testCase.hash);
  allHashes[testCase.cryptosuite] = bytesToHex(combinedHash);
  // write to commonAlg output
}
let fileName = commonAlgDir + "hashing-FALCON" + ".json";
writeFile(fileName, JSON.stringify(allHashes, null, 2));
