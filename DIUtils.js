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
export async function proofConfig(proofOptions, canonScheme = "rdfc", hash = "sha256") {
    let proofCanon;
    switch (canonScheme) {
        case "rdfc":
            let canonOptions = createCanonOptions(hash);
            proofCanon = await jsonld.canonize(proofOptions, canonOptions);
            return proofCanon;
        case "jcs":
            proofCanon = canonicalize(proofOptions);
            return proofCanon;
        default:
            throw new Error("Bad canonicalization option");
    }
}

export async function transform(document, canonScheme = "rdfc", hash="sha256") {
    let docCanon;
    switch (canonScheme) {
        case "rdfc":
            let canonOptions = createCanonOptions(hash);
            docCanon = await jsonld.canonize(document, canonOptions);
            return docCanon;
        case "jcs":
            docCanon = canonicalize(document);
            return docCanon;
        default:
            throw new Error("Bad canonicalization option");
    }
}

export function hashing(transformedDocument, canonicalProofConfig, hash = "sha256") {
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

// Create canon options for JSON-LD canonicalization based on hash function.
function createCanonOptions(canonScheme) {
    class MessageDigest {
        constructor() {
            switch (canonScheme) {
            case "sha256":
                this.md.sha256.create();
                break;
            case "sha384":
                this.md = sha384.create();
                break;
            case "sha512":
                this.md = sha512.create();
                break;
            default:
                throw new Error("Unsupported hash function");
            }
        }
        update(msg) {
            this.md.update(msg)
        }
        digest() {
            return bytesToHex(this.md.digest())
        }
    };
    const canonOptions = {
        algorithm: 'URDNA2015',
        format: 'application/n-quads', createMessageDigest: () => new MessageDigest()
    }

    // let cannon = await jsonld.canonize(document, canonOptions);
    return canonOptions;
}