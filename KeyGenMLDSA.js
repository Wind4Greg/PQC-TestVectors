/*

    Multicode **varint** prefixes from

    mldsa-44-pub	0x1210	draft	ML-DSA 44 public key; as specified by FIPS 204
    mldsa-65-pub	0x1211	draft	ML-DSA 65 public key; as specified by FIPS 204
    mldsa-87-pub	0x1212	draft	ML-DSA 87 public key; as specified by FIPS 204

    Computed raw byte prefixes (see function `printBytePrefixes()`):

    Byte prefixes for mldsa-44-pub: 0x9024
    Byte prefixes for mldsa-65-pub: 0x9124
    Byte prefixes for mldsa-87-pub: 0x9224

*/

import { mkdir, readFile, writeFile } from 'fs/promises';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import * as utils from '@noble/hashes/utils.js';
const { bytesToHex, concatBytes, equalBytes, hexToBytes } = utils;
import pkg from 'varint';
const {encode, decode} = pkg;
import { base58btc } from 'multiformats/bases/base58'
import { base64url } from 'multiformats/bases/base64'


const prefixVarints = [
    { name: "mldsa-44-pub", codeVarint: 0x1210 },
    { name: "mldsa-65-pub", codeVarint: 0x1211 },
    { name: "mldsa-87-pub", codeVarint: 0x1212 }
];

function printBytePrefixes() {
    for (let prefixVarint of prefixVarints) {
        let intArray = encode(prefixVarint.codeVarint);
        console.log(`intArray: ${intArray instanceof(Array)}`);
        let uintStuff = new Uint8Array(intArray);
        console.log(`Byte prefixes for ${prefixVarint.name}: 0x${bytesToHex(uintStuff)}`);
        // check prefixes
        let tempArray = Array(uintStuff);
        let codeVarint = decode(uintStuff);
        console.log(`recovered varint code: ${codeVarint.toString(16)}`);
    }
}

printBytePrefixes(); // Run this if varint codes change to get raw byte prefixes
const BYTE_PRE_MLDSA_44 = new Uint8Array([0x90, 0x24]); // mldsa-44-pub: 0x9024
const BYTE_PRE_MLDSA_65 = new Uint8Array([0x91, 0x24]); // mldsa-65-pub: 0x9124
const BYTE_PRE_MLDSA_87 = new Uint8Array([0x92, 0x24]); // mldsa-87-pub: 0x9224

const baseDir = "./temp/"

const seed = randomBytes(32); // seed is optional
const keys44 = ml_dsa44.keygen(seed);
const keys65 = ml_dsa65.keygen(seed);
const keys87 = ml_dsa87.keygen(seed);
const allKeys = {
    mldsa44: {
        publicKeyHex: bytesToHex(keys44.publicKey),
        secretKeyHex: bytesToHex(keys44.secretKey),
        publicKeyMultibase: base58btc.encode(concatBytes(BYTE_PRE_MLDSA_44, keys44.publicKey))
    },
    mldsa65: {
        publicKeyHex: bytesToHex(keys65.publicKey),
        secretKeyHex: bytesToHex(keys65.secretKey),
        publicKeyMultibase: base58btc.encode(concatBytes(BYTE_PRE_MLDSA_65, keys65.publicKey))
    },
    mldsa87: {
        publicKeyHex: bytesToHex(keys87.publicKey),
        secretKeyHex: bytesToHex(keys87.secretKey),
        publicKeyMultibase: base58btc.encode(concatBytes(BYTE_PRE_MLDSA_87, keys87.publicKey))
    },
}

writeFile(baseDir + 'KeysMLDSA.json', JSON.stringify(allKeys, null, 2));
// const msg = new TextEncoder().encode('hello noble');
// const sig = ml_dsa65.sign(msg, keys.secretKey);
// const isValid = ml_dsa65.verify(sig, msg, keys.publicKey);
