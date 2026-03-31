/*

    Multicode **varint** prefixes chosen by me for now

    falcon-512-pub	0x122c	
    falcon-1024-pub 0x122d

    Computed raw byte prefixes (see function `printBytePrefixes()`):

    Byte prefixes for falcon-512-pub: 0xac24
    Byte prefixes for falcon-1024-pub: 0xad24

*/

import { mkdir, readFile, writeFile } from "fs/promises";
import { falcon512, falcon1024 } from  "@noble/post-quantum/falcon.js"
import { randomBytes } from "@noble/post-quantum/utils.js";
import * as utils from "@noble/hashes/utils.js";
const { bytesToHex, concatBytes, equalBytes, hexToBytes } = utils;
import pkg from "varint";
const { encode, decode } = pkg;
import { base64url } from "multiformats/bases/base64";

const prefixVarints = [
  { name: "falcon-512-pub", codeVarint: 0x122c },
  { name: "falcon-1024-pub", codeVarint: 0x122d },
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
const BYTE_PRE_FALCON_512 = new Uint8Array([0xac, 0x24]); 
const BYTE_PRE_FALCON_1024 = new Uint8Array([0xad, 0x24]);


const baseDir = "./temp/";
const seed1 = randomBytes(48); // seed is optional
const keys512 = falcon512.keygen(seed1);
const keys1024 = falcon1024.keygen(seed1);
const allKeys = {
  falcon512: {
    publicKeyHex: bytesToHex(keys512.publicKey),
    secretKeyHex: bytesToHex(keys512.secretKey),
    publicKeyMultibase: base64url.encode(
      concatBytes(BYTE_PRE_FALCON_512, keys512.publicKey),
    ),
  },
  falcon1024: {
    publicKeyHex: bytesToHex(keys1024.publicKey),
    secretKeyHex: bytesToHex(keys1024.secretKey),
    publicKeyMultibase: base64url.encode(
      concatBytes(BYTE_PRE_FALCON_1024, keys1024.publicKey),
    ),
  },
};

writeFile(baseDir + "KeysFALCON.json", JSON.stringify(allKeys, null, 2));
// const msg = new TextEncoder().encode('hello noble');
// const sig = falcon512.sign(msg, keys512.secretKey);
// const isValid = falcon512.verify(sig, msg, keys.publicKey);
