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
    cryptosuite: "mldsa44-rdfc-2024",
    canonScheme: "rdfc",
    hash: "sha256",
    outputDir: "./output/mldsa44-rdfc-2024/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysMLDSA.json",
    keyType: "mldsa44",
  },
  {
    cryptosuite: "mldsa44-jcs-2024",
    canonScheme: "jcs",
    hash: "sha256",
    outputDir: "./output/mldsa44-jcs-2024/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysMLDSA.json",
    keyType: "mldsa44",
  },
  {
    cryptosuite: "mldsa65-rdfc-2024",
    canonScheme: "rdfc",
    hash: "sha384",
    outputDir: "./output/mldsa65-rdfc-2024/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysMLDSA.json",
    keyType: "mldsa65",
  },
  {
    cryptosuite: "mldsa65-jcs-2024",
    canonScheme: "jcs",
    hash: "sha384",
    outputDir: "./output/mldsa65-jcs-2024/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysMLDSA.json",
    keyType: "mldsa65",
  },
  {
    cryptosuite: "mldsa87-rdfc-2024",
    canonScheme: "rdfc",
    hash: "sha512",
    outputDir: "./output/mldsa87-rdfc-2024/alumni/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysMLDSA.json",
    keyType: "mldsa87",
  },
  {
    cryptosuite: "mldsa87-jcs-2024",
    canonScheme: "jcs",
    hash: "sha512",
    outputDir: "./output/mldsa87-jcs-2024/alumni/",
    inputFile: "./input/unsigned.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysMLDSA.json",
    keyType: "mldsa87",
  },
];

for (let testCase of testCases) {
  // Create output directory for the results
  const baseDir = testCase.outputDir;
  let status = await mkdir(baseDir, { recursive: true });
  status = await mkdir(commonAlgDir, { recursive: true });

  let allKeys = JSON.parse(
    await readFile(new URL(testCase.keyFile, import.meta.url)),
  );
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
    "did:key:" + publicKeyMultibase + "#" + publicKeyMultibase;

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
let fileName = commonAlgDir + "hashing-MLDSA" + ".json";
writeFile(fileName, JSON.stringify(allHashes, null, 2));
