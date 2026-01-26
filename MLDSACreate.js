/*
    **TODO**: Update this for PQC and generalized processing


    Steps to create a signed verifiable credential with an *EcdsaSecp256r1Signature2019*
    based on "DataIntegrityProof" representation. This has not be specified in a draft yet.
*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import { base58btc } from "multiformats/bases/base58";
import * as utils from '@noble/hashes/utils.js';
const { bytesToHex, hexToBytes } = utils;
import { proofConfig, transform, hashing } from './DIUtils.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { base64url } from 'multiformats/bases/base64'

// General scheme parameters
const canonScheme = "rdfc";
const hash = "sha256";


const dirsAndFiles = {
  outputDir: './output/mldsa44-rdfc-2024/alumni/',
  inputFile: './input/unsigned.json',
  proofOptionsFile: './input/proofOptions.json',
  keyFile: './input/KeysMLDSA.json'

}

// Create output directory for the results
const baseDir = dirsAndFiles.outputDir;
let status = await mkdir(baseDir, {recursive: true});

// TODO MLDSA44 keys
let allKeys = JSON.parse(
    await readFile(
      new URL(dirsAndFiles.keyFile, import.meta.url)
    )
  );
const publicKeyMultibase = allKeys.mldsa44.publicKeyMultibase;
let secretKey = hexToBytes(allKeys.mldsa44.secretKeyHex);
let publicKey = hexToBytes(allKeys.mldsa44.publicKeyHex);

// Read input document from a file or just specify it right here.
let document = JSON.parse(
    await readFile(
      new URL(dirsAndFiles.inputFile, import.meta.url)
    )
  );

// Signed Document Creation Steps:

// Transform the document
let docCannon = await transform(document, canonScheme);
writeFile(baseDir + 'transformDocMLDSA44.txt', docCannon);


// Set proof options
let proofOptions = JSON.parse(
    await readFile(
      new URL(dirsAndFiles.proofOptionsFile, import.meta.url)
    )
  );
// Must specify cryptosuite
proofOptions.cryptosuite = "mldsa44-rdfc-2019";
// Must provide verification methods related to public key
proofOptions.verificationMethod = 'did:key:' + publicKeyMultibase + '#'
  + publicKeyMultibase;

proofOptions["@context"] = document["@context"];
// Proof Configuration
let proofCanon = await proofConfig(proofOptions, canonScheme);
console.log("Proof Configuration Canonized:");
// console.log(proofCanon);
writeFile(baseDir + 'proofCanonMLDSA44.txt', proofCanon);

// Hashing
let combinedHash = hashing(docCannon, proofCanon, hash);
writeFile(baseDir + 'combinedHashMLDSA44.txt', bytesToHex(combinedHash));

// Sign
let signature = ml_dsa44.sign(combinedHash, secretKey);
console.log("MLDSA44 based signature:")
console.log(signature.length);
writeFile(baseDir + 'sigHexMLDSA44.txt', bytesToHex(signature));
console.log("Computed Signature from private key:");
// console.log(base64url.encode(signature));
writeFile(baseDir + 'sigBase64urlMLDSA44.txt', base64url.encode(signature));

// Verify (just to see we have a good private/public pair)
let pbk = base58btc.decode(publicKeyMultibase);
pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
// console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`);
let result = ml_dsa44.verify(signature, combinedHash, pbk);
console.log(`Signature verified: ${result}`);

// Construct Signed Document
let signedDocument = Object.assign({}, document);
delete proofOptions['@context'];
signedDocument.proof = proofOptions;
signedDocument.proof.proofValue = base64url.encode(signature);

// console.log(JSON.stringify(signedDocument, null, 2));
writeFile(baseDir + 'signedMLDSA44.json', JSON.stringify(signedDocument, null, 2));

