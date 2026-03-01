/*
    ML-DSA Verification

*/
import { readFile } from "fs/promises";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { base64url } from "multiformats/bases/base64";
import { proofConfig, transform, hashing } from "./DIUtils.js";
import { bytesToHex } from "@noble/hashes/utils.js";

let testCases = [
  {
    cryptosuite: "mldsa44-rdfc-2024",
    sigFunc: ml_dsa44,
    canonScheme: "rdfc",
    hash: "sha256",
    signedDoc: "./output/mldsa44-rdfc-2024/signed-mldsa44-rdfc-2024.json",
  },
  {
    cryptosuite: "mldsa44-jcs-2024",
    sigFunc: ml_dsa44,
    canonScheme: "jcs",
    hash: "sha256",
    signedDoc: "./output/mldsa44-jcs-2024/signed-mldsa44-jcs-2024.json",
  },
  {
    cryptosuite: "mldsa65-rdfc-2024",
    sigFunc: ml_dsa65,
    canonScheme: "rdfc",
    hash: "sha384",
    signedDoc: "./output/mldsa65-rdfc-2024/signed-mldsa65-rdfc-2024.json",
  },
  {
    cryptosuite: "mldsa65-jcs-2024",
    sigFunc: ml_dsa65,
    canonScheme: "jcs",
    hash: "sha384",
    signedDoc: "./output/mldsa65-jcs-2024/signed-mldsa65-jcs-2024.json",
  },
  {
    cryptosuite: "mldsa87-rdfc-2024",
    sigFunc: ml_dsa87,
    canonScheme: "rdfc",
    hash: "sha512",
    signedDoc: "./output/mldsa87-rdfc-2024/signed-mldsa87-rdfc-2024.json",
  },
  {
    cryptosuite: "mldsa87-jcs-2024",
    sigFunc: ml_dsa87,
    canonScheme: "jcs",
    hash: "sha512",
    signedDoc: "./output/mldsa87-jcs-2024/signed-mldsa87-jcs-2024.json",
  },
];

for (let testCase of testCases) {
  // Read signed input document from a file or just specify it right here.
  const signedDocument = JSON.parse(
    await readFile(new URL(testCase.signedDoc, import.meta.url)),
  );

  // Document without proof
  let document = Object.assign({}, signedDocument);
  delete document.proof;
  // console.log(document);

  // Transform the document
  let docCanon = await transform(document, testCase.canonScheme, testCase.hash);
  // console.log("Canonized unsigned document:")
  // console.log(docCanon);

  // Set proof options per draft
  let proofOptions = {};
  proofOptions.type = signedDocument.proof.type;
  proofOptions.cryptosuite = signedDocument.proof.cryptosuite;
  proofOptions.created = signedDocument.proof.created;
  proofOptions.verificationMethod = signedDocument.proof.verificationMethod;
  proofOptions.proofPurpose = signedDocument.proof.proofPurpose;
  proofOptions["@context"] = signedDocument["@context"];

  // proof config
  let proofCanon = await proofConfig(proofOptions, testCase.canonScheme);
  // console.log("Proof Configuration Canonized:");
  // console.log(proofCanon);

  // Hashing
  let combinedHash = hashing(docCanon, proofCanon, testCase.hash);
  // console.log(
  //   `Test: ${testCase.cryptosuite}, combineHash: ${bytesToHex(combinedHash)}`,
  // );

  // Get public key
  let encodedPbk = signedDocument.proof.verificationMethod.split("#")[1];
  let pbk = base64url.decode(encodedPbk);
  pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
  // console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);

  // Verify
  let signature = base64url.decode(signedDocument.proof.proofValue);
  let result = testCase.sigFunc.verify(signature, combinedHash, pbk);
  console.log(`Signed document: ${testCase.signedDoc}`);
  console.log(`Signature verified: ${result}`);
}
