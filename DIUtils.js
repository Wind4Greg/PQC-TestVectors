/* General purpose utilities for VC Data Integrity processing.
   Non-selective disclosure case.

*/
import jsonld from 'jsonld'; // For RDFC
import { localLoader } from './documentLoader.js';
import canonicalize from 'canonicalize'; // For JCS
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import * as utils from '@noble/hashes/utils.js';
const { bytesToHex, concatBytes, equalBytes, hexToBytes } = utils;

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

// TODO: for non SHA-256 case RDFC needs hash info...
export async function proofConfig(proofOptions, canonScheme="rdfc") {
    let proofCanon;
    switch (canonScheme) {
        case "rdfc":
            proofCanon = await jsonld.canonize(proofOptions);
            return proofCanon;
        case "jcs":
            proofCanon = canonicalize(proofOptions);
            return proofCanon;
        default:
            throw new Error("Bad canonicalization option");
    }
}

export async function transform(document, canonScheme="rdfc") {
    let proofCanon;
    switch (canonScheme) {
        case "rdfc":
            proofCanon = await jsonld.canonize(document);
            return proofCanon;
        case "jcs":
            proofCanon = canonicalize(document);
            return proofCanon;
        default:
            throw new Error("Bad canonicalization option");
    }
}

export function hashing (transformedDocument, canonicalProofConfig, hash="sha256") {
    const encoder = new TextEncoder(); // Use encoder to convert to Uint8Array
    let hashFunc;
    switch (hash) {
        case "sha256":
            hashFunc = sha256;
            break;
        case "sha384":
            hashFunc = sha384;
            break;
        case "sha512":
            hashFunc = sha512;
            break;
        default:
            throw new Error("Unsupported hash function");
    }
    let docHash = hashFunc(encoder.encode(transformedDocument));
    let proofHash = sha256(encoder.encode(canonicalProofConfig));
    let combinedHash = concatBytes(proofHash, docHash);
    return combinedHash;
}