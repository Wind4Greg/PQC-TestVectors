/*
ML-DSA test vector generation for both RDFC, JCS and multiple security strengths.

FIPS 204 info:

| Name     | Private Key | Public Key | Signature Size | Sec Strength |
|----------|-------------|------------|----------------|--------------|
|ML-DSA-44 | 2528        | 1312       | 2420           | Category 2   |
|ML-DSA-65 | 4000        | 1952       | 3293           | Category 3   |
|ML-DSA-87 | 4864        | 2592       | 4595           | Category 5   |

Hash collision resistance strength:

| Sec Strength | Hash Function |
|--------------|---------------|
| Cat 1 or 2   | SHA-256       |
| Cat 3 or 4   | SHA-384       |
| Cat 5        | SHA-512       |

*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import { base58btc } from "multiformats/bases/base58";
import * as utils from '@noble/hashes/utils.js';
const { bytesToHex, hexToBytes } = utils;
import { proofConfig, transform, hashing } from './DIUtils.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { base64url } from 'multiformats/bases/base64'

// General scheme parameters

let testCases = [
  {
    cryptosuite: "mldsa44-rdfc-2019",
    sigFunc: ml_dsa44,
    cannonScheme: "rdfc",
    hash: "sha256",
    outputDir: './output/mldsa44-rdfc-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysMLDSA.json',
    keyType: "mldsa44"
  },
  {
    cryptosuite: "mldsa44-jcs-2019",
    sigFunc: ml_dsa44,
    cannonScheme: "jcs",
    hash: "sha256",
    outputDir: './output/mldsa44-jcs-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysMLDSA.json',
    keyType: "mldsa44"
  },
    {
    cryptosuite: "mldsa65-rdfc-2019",
    sigFunc: ml_dsa65,
    cannonScheme: "rdfc",
    hash: "sha384",
    outputDir: './output/mldsa65-rdfc-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysMLDSA.json',
    keyType: "mldsa65"
  },
  {
    cryptosuite: "mldsa65-jcs-2019",
    sigFunc: ml_dsa65,
    cannonScheme: "jcs",
    hash: "sha384",
    outputDir: './output/mldsa65-jcs-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysMLDSA.json',
    keyType: "mldsa65"
  },
      {
    cryptosuite: "mldsa87-rdfc-2019",
    sigFunc: ml_dsa87,
    cannonScheme: "rdfc",
    hash: "sha512",
    outputDir: './output/mldsa87-rdfc-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysMLDSA.json',
    keyType: "mldsa87"
  },
  {
    cryptosuite: "mldsa87-jcs-2019",
    sigFunc: ml_dsa87,
    cannonScheme: "jcs",
    hash: "sha384",
    outputDir: './output/mldsa87-jcs-2024/alumni/',
    inputFile: './input/unsigned.json',
    proofOptionsFile: './input/proofOptions.json',
    keyFile: './input/KeysMLDSA.json',
    keyType: "mldsa87"
  },
]

for (let testCase of testCases) {
  // Create output directory for the results
  const baseDir = testCase.outputDir;
  let status = await mkdir(baseDir, { recursive: true });

  // TODO MLDSA44 keys
  let allKeys = JSON.parse(
    await readFile(
      new URL(testCase.keyFile, import.meta.url)
    )
  );
  const publicKeyMultibase = allKeys[testCase.keyType].publicKeyMultibase;
  let secretKey = hexToBytes(allKeys[testCase.keyType].secretKeyHex);
  let publicKey = hexToBytes(allKeys[testCase.keyType].publicKeyHex);

  // Read input document from a file or just specify it right here.
  let document = JSON.parse(
    await readFile(
      new URL(testCase.inputFile, import.meta.url)
    )
  );

  // Signed Document Creation Steps:

  // Transform the document
  let docCannon = await transform(document, testCase.canonScheme, testCase.hash);
  // writeFile(baseDir + 'transformDocMLDSA44.txt', docCannon);


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
  console.log("Proof Configuration Canonized:");
  // console.log(proofCanon);
  // writeFile(baseDir + 'proofCanonMLDSA44.txt', proofCanon);

  // Hashing
  let combinedHash = hashing(docCannon, proofCanon, testCase.hash);
  // writeFile(baseDir + 'combinedHashMLDSA44.txt', bytesToHex(combinedHash));

  // Sign
  let signature = testCase.sigFunc.sign(combinedHash, secretKey);
  // console.log("MLDSA44 based signature:")
  // console.log(signature.length);
  writeFile(baseDir + 'sigHex' + testCase.keyType + '.txt', bytesToHex(signature));
  console.log("Computed Signature from private key:");
  // console.log(base64url.encode(signature));
  writeFile(baseDir + 'sigBase64url' + testCase.keyType + '.txt', base64url.encode(signature));

  // Verify (just to see we have a good private/public pair)
  let pbk = base58btc.decode(publicKeyMultibase);
  pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
  // console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
  let result = testCase.sigFunc.verify(signature, combinedHash, pbk);
  console.log(`Signature verified: ${result}`);

  // Construct Signed Document
  let signedDocument = Object.assign({}, document);
  delete proofOptions['@context'];
  signedDocument.proof = proofOptions;
  signedDocument.proof.proofValue = base64url.encode(signature);

  // console.log(JSON.stringify(signedDocument, null, 2));
  writeFile(baseDir + 'signed' + testCase.keyType + '.json', JSON.stringify(signedDocument, null, 2));
}
