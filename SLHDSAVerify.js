/*
    SLH-DSA Verification

*/
import { readFile } from "fs/promises";
import { base58btc } from "multiformats/bases/base58";
import {
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256s,
} from "@noble/post-quantum/slh-dsa.js";
import { base64url } from "multiformats/bases/base64";
import { proofConfig, transform, hashing } from "./DIUtils.js";

let testCases = [
  {
    cryptosuite: "slhdsa128-rdfc-2024",
    sigFunc: slh_dsa_sha2_128s,
    canonScheme: "rdfc",
    hash: "sha256",
    signedDoc: "./output/slhdsa128-rdfc-2024/signed-slhdsa128-rdfc-2024.json",
  },
  {
    cryptosuite: "slhdsa128-jcs-2024",
    sigFunc: slh_dsa_sha2_128s,
    canonScheme: "jcs",
    hash: "sha256",
    signedDoc: "./output/slhdsa128-jcs-2024/signed-slhdsa128-jcs-2024.json",
  },
  {
    cryptosuite: "slhdsa192-rdfc-2024",
    sigFunc: slh_dsa_sha2_192s,
    canonScheme: "rdfc",
    hash: "sha384",
    signedDoc: "./output/slhdsa192-rdfc-2024/signed-slhdsa192-rdfc-2024.json",
  },
  {
    cryptosuite: "slhdsa192-jcs-2024",
    sigFunc: slh_dsa_sha2_192s,
    canonScheme: "jcs",
    hash: "sha384",
    signedDoc: "./output/slhdsa192-jcs-2024/signed-slhdsa192-jcs-2024.json",
  },
  {
    cryptosuite: "slhdsa256-rdfc-2024",
    sigFunc: slh_dsa_sha2_256s,
    canonScheme: "rdfc",
    hash: "sha512",
    signedDoc: "./output/slhdsa256-rdfc-2024/signed-slhdsa256-rdfc-2024.json",
  },
  {
    cryptosuite: "slhdsa256-jcs-2024",
    sigFunc: slh_dsa_sha2_256s,
    canonScheme: "jcs",
    hash: "sha512",
    signedDoc: "./output/slhdsa256-jcs-2024/signed-slhdsa256-jcs-2024.json",
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

  // Transform the document
  let docCanon = await transform(document, testCase.canonScheme, testCase.hash);
  // console.log("Canonized unsigned document:")

  // Set proof options per draft
  let proofOptions = {};
  proofOptions.type = signedDocument.proof.type;
  proofOptions.cryptosuite = signedDocument.proof.cryptosuite;
  proofOptions.created = signedDocument.proof.created;
  proofOptions.verificationMethod = signedDocument.proof.verificationMethod;
  proofOptions.proofPurpose = signedDocument.proof.proofPurpose;
  proofOptions["@context"] = signedDocument["@context"];

  // proof config
  let proofCanon = await proofConfig(
    proofOptions,
    testCase.canonScheme,
    testCase.hash,
  );

  // Hashing
  let combinedHash = hashing(docCanon, proofCanon, testCase.hash);

  // Get public key
  let encodedPbk = signedDocument.proof.verificationMethod.split("#")[1];
  let pbk = base64url.decode(encodedPbk);
  pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator

  // Verify
  let signature = base64url.decode(signedDocument.proof.proofValue);
  let result = testCase.sigFunc.verify(signature, combinedHash, pbk);
  console.log(`Signed document: ${testCase.signedDoc}`);
  console.log(`Signature verified: ${result}`);
}
