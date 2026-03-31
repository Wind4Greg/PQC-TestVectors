/*
    FALCON Verification

*/
import { readFile } from "fs/promises";
import { falcon512, falcon1024 } from  "@noble/post-quantum/falcon.js";
import { base64url } from "multiformats/bases/base64";
import { proofConfig, transform, hashing } from "./DIUtils.js";
import { bytesToHex } from "@noble/hashes/utils.js";

let testCases = [
  {
    cryptosuite: "falcon512-rdfc-2024",
    sigFunc: falcon512,
    canonScheme: "rdfc",
    hash: "sha256",
    signedDoc: "./output/falcon512-rdfc-2024/signed-falcon512-rdfc-2024.json",
  },
  {
    cryptosuite: "falcon512-jcs-2024",
    sigFunc: falcon512,
    canonScheme: "jcs",
    hash: "sha256",
    signedDoc: "./output/falcon512-jcs-2024/signed-falcon512-jcs-2024.json",
  },
  {
    cryptosuite: "falcon1024-rdfc-2024",
    sigFunc: falcon1024,
    canonScheme: "rdfc",
    hash: "sha512",
    signedDoc: "./output/falcon1024-rdfc-2024/signed-falcon1024-rdfc-2024.json",
  },
  {
    cryptosuite: "falcon1024-jcs-2024",
    sigFunc: falcon1024,
    canonScheme: "jcs",
    hash: "sha512",
    signedDoc: "./output/falcon1024-jcs-2024/signed-falcon1024-jcs-2024.json",
  }
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
  let encodedPbk = signedDocument.proof.verificationMethod.split("did:key:")[1];
  let pbk = base64url.decode(encodedPbk);
  pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
  // console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);

  // Verify
  let signature = base64url.decode(signedDocument.proof.proofValue);
  let result = testCase.sigFunc.verify(signature, combinedHash, pbk);
  console.log(`Signed document: ${testCase.signedDoc}`);
  console.log(`Signature verified: ${result}`);
}
