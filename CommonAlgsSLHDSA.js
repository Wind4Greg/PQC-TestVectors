/*
Test vector generation for common algorithms: Proof Configuration, Transform,
and Hashing.

Since the cryptosuite name appears in the `proof options` the Proof Options and
Hashing algorithms outputs are dependent on this.

*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import { base58btc } from "multiformats/bases/base58";
import * as utils from '@noble/hashes/utils.js';
const { bytesToHex, hexToBytes } = utils;
import { proofConfig, transform, hashing } from './DIUtils.js';

const commonAlgDir = './output/commonAlgs/';
const allHashes = {};

let testCases = [
  {
    cryptosuite: "slhdsa128-rdfc-2024",
    cannonScheme: "rdfc",
    hash: "sha256",
    outputDir: './output/slhdsa128-rdfc-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysSLHDSA.json',
    keyType: "slh128s"
  },
  {
    cryptosuite: "slhdsa128-jcs-2024",
    cannonScheme: "jcs",
    hash: "sha256",
    outputDir: './output/slhdsa128-jcs-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysSLHDSA.json',
    keyType: "slh128s"
  },
  {
    cryptosuite: "slhdsa192-rdfc-2024",
    cannonScheme: "rdfc",
    hash: "sha384",
    outputDir: './output/slhdsa192-rdfc-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysSLHDSA.json',
    keyType: "slh192s"
  },
  {
    cryptosuite: "slhdsa192-jcs-2024",
    cannonScheme: "jcs",
    hash: "sha384",
    outputDir: './output/slhdsa192-jcs-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysSLHDSA.json',
    keyType: "slh192s"
  },
  {
    cryptosuite: "slhdsa256-rdfc-2024",
    cannonScheme: "rdfc",
    hash: "sha512",
    outputDir: './output/slhdsa256-rdfc-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysSLHDSA.json',
    keyType: "slh256s"
  },
  {
    cryptosuite: "slhdsa256-jcs-2024",
    cannonScheme: "jcs",
    hash: "sha512",
    outputDir: './output/slhdsa256-jcs-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysSLHDSA.json',
    keyType: "slh256s"
  },
]

for (let testCase of testCases) {
  // Create output directory for the results
  const baseDir = testCase.outputDir;
  let status = await mkdir(baseDir, { recursive: true });
  status = await mkdir(commonAlgDir, { recursive: true });

  let allKeys = JSON.parse(
    await readFile(
      new URL(testCase.keyFile, import.meta.url)
    )
  );
  const publicKeyMultibase = allKeys[testCase.keyType].publicKeyMultibase;

  // Read input document from a file or just specify it right here.
  let document = JSON.parse(
    await readFile(
      new URL(testCase.inputFile, import.meta.url)
    )
  );

  // Common Algorithms

  // Transform the document
  let docCanon = await transform(document, testCase.canonScheme, testCase.hash);
  // write to commonAlg output
  let fileName = commonAlgDir + 'transform-' + testCase.canonScheme + '-' + testCase.hash + '.txt';
  writeFile(fileName, docCanon);
  // Set proof options
  let proofOptions = JSON.parse(
    await readFile(
      new URL(testCase.proofOptionsFile, import.meta.url)
    )
  );
  // Must specify cryptosuite
  proofOptions.cryptosuite = testCase.cryptosuite;
  // Must provide verification methods related to public key
  proofOptions.verificationMethod = 'did:key:' + publicKeyMultibase + '#'
    + publicKeyMultibase;

  proofOptions["@context"] = document["@context"];
  // Proof Configuration
  let proofCanon = await proofConfig(proofOptions, testCase.canonScheme, testCase.hash);
  // write to commonAlg output
  fileName = commonAlgDir + 'proofConfig-' + testCase.cryptosuite + '.txt';
  writeFile(fileName, proofCanon);

  // Hashing
  let combinedHash = hashing(docCanon, proofCanon, testCase.hash);
  allHashes[testCase.cryptosuite] = bytesToHex(combinedHash);
  // write to commonAlg output
}
let fileName = commonAlgDir + 'hashing-SLHDSA' + '.json';
writeFile(fileName, JSON.stringify(allHashes, null, 2));
