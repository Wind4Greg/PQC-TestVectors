/*

Multicode **varint** prefixes tentative (sha2, small sig variants):

slhdsa-sha2-128s-pub,   0x1220,
slhdsa-sha2-192s-pub,   0x1224,
slhdsa-sha2-256s-pub,   0x1228,

Computed raw byte prefixes (see function `printBytePrefixes()`):

Byte prefixes for slhdsa-sha2-128s-pub: 0xa024
Byte prefixes for slhdsa-sha2-192s-pub: 0xa424
Byte prefixes for slhdsa-sha2-256s-pub: 0xa824

*/

import { mkdir, readFile, writeFile } from "fs/promises";
import {
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256s,
} from "@noble/post-quantum/slh-dsa.js";
import { randomBytes } from "@noble/post-quantum/utils.js";
import * as utils from "@noble/hashes/utils.js";
const { bytesToHex, concatBytes, equalBytes, hexToBytes } = utils;
import pkg from "varint";
const { encode, decode } = pkg;
import { base64url } from "multiformats/bases/base64";

const prefixVarints = [
  { name: "slhdsa-sha2-128s-pub", codeVarint: 0x1220 },
  { name: "slhdsa-sha2-192s-pub", codeVarint: 0x1224 },
  { name: "slhdsa-sha2-256s-pub", codeVarint: 0x1228 },
];

function printBytePrefixes() {
  for (let prefixVarint of prefixVarints) {
    let intArray = encode(prefixVarint.codeVarint);
    console.log(`intArray: ${intArray instanceof Array}`);
    let uintStuff = new Uint8Array(intArray);
    console.log(
      `Byte prefixes for ${prefixVarint.name}: 0x${bytesToHex(uintStuff)}`,
    );
    // check prefixes
    let tempArray = Array(uintStuff);
    let codeVarint = decode(uintStuff);
    console.log(`recovered varint code: ${codeVarint.toString(16)}`);
  }
}

printBytePrefixes(); // Run this if varint codes change to get raw byte prefixes
const SLHDSA_SHA2_128S = new Uint8Array([0xa0, 0x24]);
const SLHDSA_SHA2_192S = new Uint8Array([0xa4, 0x24]);
const SLHDSA_SHA2_256S = new Uint8Array([0xa8, 0x24]);

const baseDir = "./temp/";

const keys128 = slh_dsa_sha2_128s.keygen();
const keys192 = slh_dsa_sha2_192s.keygen();
const keys256 = slh_dsa_sha2_256s.keygen();
const allKeys = {
  slh128s: {
    publicKeyHex: bytesToHex(keys128.publicKey),
    secretKeyHex: bytesToHex(keys128.secretKey),
    publicKeyMultibase: base64url.encode(
      concatBytes(SLHDSA_SHA2_128S, keys128.publicKey),
    ),
  },
  slh192s: {
    publicKeyHex: bytesToHex(keys192.publicKey),
    secretKeyHex: bytesToHex(keys192.secretKey),
    publicKeyMultibase: base64url.encode(
      concatBytes(SLHDSA_SHA2_192S, keys192.publicKey),
    ),
  },
  slh256s: {
    publicKeyHex: bytesToHex(keys256.publicKey),
    secretKeyHex: bytesToHex(keys256.secretKey),
    publicKeyMultibase: base64url.encode(
      concatBytes(SLHDSA_SHA2_256S, keys256.publicKey),
    ),
  },
};

writeFile(baseDir + "KeysSLHDSA.json", JSON.stringify(allKeys, null, 2));
// Example Signature and verification.
// const msg = new TextEncoder().encode('hello noble');
// let startTime = new Date();
// const sig = slh_dsa_sha2_128s.sign(msg, keys128.secretKey);
// let endTime = new Date();
// console.log(`Signature generation time: ${endTime - startTime}`);
// console.log("Example signature:");
// console.log(bytesToHex(sig));
// startTime = new Date();
// const isValid = slh_dsa_sha2_128s.verify(sig, msg, keys128.publicKey);
// endTime = new Date();
// console.log(`Signature validation time: ${endTime - startTime}`);
// console.log(`Signature valid: ${isValid}`);
