/*
SQIsign test vector generation for both RDFC, JCS and multiple security strengths.

|Name 	     | Security 	| Private Key |	Public Key |	Signature |
|SQIsign-I   | Category 1 |	353         |	65         |	148       |
|SQIsign-III | Category 3 |	529         |	97         |	224       |
|SQIsign-V 	 | Category 5 |	701         | 129        |	292       |

FIPS 204 info:

Hash collision resistance strength:

| Sec Strength | Hash Function |
|--------------|---------------|
| Cat 1 or 2   | SHA-256       |
| Cat 3 or 4   | SHA-384       |
| Cat 5        | SHA-512       |

Currently only doing SQIsign-1 signatures since pulling in values generated  by
an external C program that is manually run.

*/

import { mkdir, readFile, writeFile } from "fs/promises";
import * as utils from "@noble/hashes/utils.js";
const { bytesToHex, hexToBytes } = utils;
import { proofConfig, transform, hashing } from "./DIUtils.js";
import { base64url } from "multiformats/bases/base64";

function sqiSign1Dummy(combinedHash, secretKey) {
  const knownHashes = [
    "f35e179a21495698798ec6f982353e16bea9d14374ab9b659cd0afebcb1417c903f59e5b04ab575b1172cb684f22eede72f0e9033e0b5c67d0e2506768d6ce11",
    "4c1d4ef51ede749b051fb4b471e7da7d3c37af030fdd66323922fc89ef4a7dfa6ca388adaff807c71d063f666548493ba60c8c0fa109b3dd1e2564d61abe09cc",
  ];
  const signatures = [
    "f798bf541f014e3bd2096552ebcaf4ca784bb3199147143f34d855abe3df1a0325116924d968b0d5daa9370bb7772d26d1f0c6ae02ad9801e923e0531f74b20200079b63ce4e4e0b64d4311528127097358e1b962a237915bea7b60fb944df97d2ffdff643dc82d8bce7ff3d36ced9539ba5df7adc6381f39223f4bdd0d2327ba842c5a5cd9ea4c10398f9cafc0e5ce038011111",
    "236ff6db67b116ad4d5e0f2158c16c10d6e1429d7b5d6b0fcdcf31534549230258e9b21ca8e747984a66a87472b173fd74f4b430be9979e5654f9b4db11c85040000181bec717d43e332a30db86114d12e156d11c8a07145a5280b1ce967387f22af8b982b152d0f160d08728134104dbc16a36d338b5d7633335338c5371facd4648776abe9918e966dbb36b18d8fd073010b06",
  ];
  let hashHex = bytesToHex(combinedHash);
  let sigIndex = knownHashes.indexOf(hashHex);
  if (sigIndex == -1) {
    throw  new  Error("Unknown hash value to dummy SQIsign!!!");
  }
  return hexToBytes(signatures[sigIndex]);
}

let testCases = [
  {
    cryptosuite: "sqisign1-rdfc-2024",
    sigFunc: sqiSign1Dummy,
    canonScheme: "rdfc",
    hash: "sha256",
    outputDir: "./output/sqisign1-rdfc-2024/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysSQIsign.json",
    keyType: "sqisign1",
  },
  {
    cryptosuite: "sqisign1-jcs-2024",
    sigFunc: sqiSign1Dummy,
    canonScheme: "jcs",
    hash: "sha256",
    outputDir: "./output/sqisign1-jcs-2024/",
    inputFile: "./input/employmentAuth.json",
    proofOptionsFile: "./input/proofOptions.json",
    keyFile: "./input/KeysSQIsign.json",
    keyType: "sqisign1",
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
  proofOptions.verificationMethod = "did:key:" + publicKeyMultibase;

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
  let signature = testCase.sigFunc(combinedHash, secretKey);
  // writeFile(
  //   baseDir + "sigHex" + testCase.keyType.toUpperCase() + ".txt",
  //   bytesToHex(signature),
  // );
  // writeFile(
  //   baseDir + "sigBase64url" + testCase.keyType.toUpperCase() + ".txt",
  //   base64url.encode(signature),
  // );
  // Verify (just to see we have a good private/public pair)
  // let pbk = base64url.decode(publicKeyMultibase);
  // pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
  // // console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
  // let result = testCase.sigFunc.verify(signature, combinedHash, pbk);
  // console.log(`Signature verified: ${result}`);
  // console.log(`Signature size: ${signature.length}`);

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
