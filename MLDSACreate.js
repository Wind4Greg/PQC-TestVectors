/*
    **TODO**: Update this for PQC and generalized processing


    Steps to create a signed verifiable credential with an *EcdsaSecp256r1Signature2019*
    based on "DataIntegrityProof" representation. This has not be specified in a draft yet.
*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import jsonld from 'jsonld';
import { localLoader } from './documentLoader.js';
import { base58btc } from "multiformats/bases/base58";
import { p256 as P256} from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as utils from '@noble/hashes/utils.js';
const { bytesToHex, hexToBytes } = utils;
import { proofConfig, transform, hashing } from './DIUtils.js';

// General scheme parameters
const canonScheme = "rdfc";
const hash = "sha256";

// const dirsAndFiles = {
//   outputDir: './output/ecdsa-rdfc-2019-p256/',
//   inputFile: './input/unsigned.json'
// }

const dirsAndFiles = {
  outputDir: './output/ecdsa-rdfc-2019-p256/employ/',
  inputFile: './input/employmentAuth.json'
}

// Create output directory for the results
const baseDir = dirsAndFiles.outputDir;
let status = await mkdir(baseDir, {recursive: true});

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

const keyPair = {
    publicKeyMultibase: "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
};


let privateKey = hexToBytes("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
let publicKey = P256.getPublicKey(privateKey);

// Read input document from a file or just specify it right here.
let document = JSON.parse(
    await readFile(
      new URL(dirsAndFiles.inputFile, import.meta.url)
    )
  );

// Signed Document Creation Steps:

// Canonize the document
let docCannon = await transform(document, canonScheme);
console.log("Canonized unsigned document:")
console.log(docCannon);
writeFile(baseDir + 'canonDocECDSAP256.txt', docCannon);


// Set proof options per draft
let proofOptions = {};
proofOptions.type = "DataIntegrityProof";
proofOptions.cryptosuite = "ecdsa-rdfc-2019";
proofOptions.created = "2023-02-24T23:36:38Z";
// proofOptions.verificationMethod = "https://vc.example/issuers/5678#" + keyPair.publicKeyMultibase;
proofOptions.verificationMethod = 'did:key:' + keyPair.publicKeyMultibase + '#'
  + keyPair.publicKeyMultibase;
proofOptions.proofPurpose = "assertionMethod";
proofOptions["@context"] = document["@context"]; // Missing from draft!!!
console.log(proofOptions);
writeFile(baseDir + 'proofOptionsECDSAP256.json', JSON.stringify(proofOptions, null, 2));

// canonize the proof config
let proofCanon = await proofConfig(proofOptions, canonScheme);
console.log("Proof Configuration Canonized:");
console.log(proofCanon);
writeFile(baseDir + 'proofCanonECDSAP256.txt', proofCanon);

// Combine hashes
let combinedHash = hashing(docCannon, proofCanon, hash);
writeFile(baseDir + 'combinedHashECDSAP256.txt', bytesToHex(combinedHash));

// Sign
let msgHash = sha256(combinedHash); // Hash is done outside of the algorithm in noble/curve case.
let signature = P256.sign(msgHash, privateKey,  { prehash: false, lowS: false });
console.log("P256 based signature:")
console.log(signature);
writeFile(baseDir + 'sigHexECDSAP256.txt', bytesToHex(signature));
console.log("Computed Signature from private key:");
console.log(base58btc.encode(signature));
writeFile(baseDir + 'sigBTC58ECDSAP256.txt', base58btc.encode(signature));

// Verify (just to see we have a good private/public pair)
let pbk = base58btc.decode(keyPair.publicKeyMultibase);
pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
let result = P256.verify(signature, msgHash, pbk, { prehash: false, lowS: false });
console.log(`Signature verified: ${result}`);

// Construct Signed Document
let signedDocument = Object.assign({}, document);
delete proofOptions['@context'];
signedDocument.proof = proofOptions;
signedDocument.proof.proofValue = base58btc.encode(signature);

console.log(JSON.stringify(signedDocument, null, 2));
writeFile(baseDir + 'signedECDSAP256.json', JSON.stringify(signedDocument, null, 2));

