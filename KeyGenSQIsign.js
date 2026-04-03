/*

    Multicode **varint** prefixes chosen by me for now

    sqisign-1-pub  0x122e
    sqisign-3-pub  0x122f
    sqisign-5-pub  0x1230

    Computed raw byte prefixes (see function `printBytePrefixes()`):

    Byte prefixes for sqisign-1-pub: 0xae24
    Byte prefixes for sqisign-3-pub: 0xaf24
    Byte prefixes for sqisign-4-pub: 0xb024

    Hex key values were computed externally and place in the code below.

*/

import { mkdir, readFile, writeFile } from "fs/promises";
import { randomBytes } from "@noble/post-quantum/utils.js";
import * as utils from "@noble/hashes/utils.js";
const { bytesToHex, concatBytes, equalBytes, hexToBytes } = utils;
import pkg from "varint";
const { encode, decode } = pkg;
import { base64url } from "multiformats/bases/base64";

const prefixVarints = [
  { name: "sqisign-1-pub", codeVarint: 0x122e },
  { name: "sqisign-3-pub", codeVarint: 0x122f },
  { name: "sqisign-5-pub", codeVarint: 0x1230 },
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
const BYTE_PRE_SQI_1 = new Uint8Array([0xae, 0x24]); 
const BYTE_PRE_SQI_3 = new Uint8Array([0xaf, 0x24]);
const BYTE_PRE_SQI_5 = new Uint8Array([0xb0, 0x24]);

const baseDir = "./temp/";
const pubkey1  = "e144bdf2447d65170073bf86c3e2d241fe9c6aaae3065c1d7f4a3d0f3ce10303dd99e0b81dec4f85bca1fe5ecfa12ed2f8c2f5bc58bd751b7b1431d8640ca8030b";
const pubkey3  = "97313a3b00f5f2a96d8c4524fac8d101494deed8c231a36bba4fc925317b79f13e42c90e03c63f83aea0703b7c8f1f36f9ec7775e332e9bc953cc8026d38100d44c5f744fb2b17e249b334d99c810f2407d4db63fea187f0a0003da39c88332d06";

const allKeys = {
  sqisign1: {
    publicKeyHex: pubkey1,
    secretKeyHex: "e144bdf2447d65170073bf86c3e2d241fe9c6aaae3065c1d7f4a3d0f3ce10303dd99e0b81dec4f85bca1fe5ecfa12ed2f8c2f5bc58bd751b7b1431d8640ca8030b63790509f8c0c251959a459b7f0b6cca1f020000000000000000000000000000ec632b3911de57001f37a3d6ffbb6042ddfdffffffffffffffffffffffffffff99d5056c88aaef28a1b8980fcf58a369a7fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000024ff19b3d11ba00ecc969af6f4f1a60d36023ec86d66ed68316e613e5768ab0035262a3f5f562ee8be9a3b013b80e3bd461d630ef5b06cd587c786687a6ad500fb5dec2e9c79b6a463eeb473e545cd8a3e1daa7a525517326ab5ad633bb79900b712fad0aa36f07d70194256408072f5ba17a622b53275473fda285c47acec00",
    publicKeyMultibase: base64url.encode(
      concatBytes(BYTE_PRE_SQI_1, hexToBytes(pubkey1)),
    ),
  },
  sqisign3: {
    publicKeyHex: pubkey3,
    secretKeyHex: "97313a3b00f5f2a96d8c4524fac8d101494deed8c231a36bba4fc925317b79f13e42c90e03c63f83aea0703b7c8f1f36f9ec7775e332e9bc953cc8026d38100d44c5f744fb2b17e249b334d99c810f2407d4db63fea187f0a0003da39c88332d063bdcacee77907445c55d7c2518b68f8fdd747bed42714fa89f05000000000000000000000000000000000000000000003487aa4aeb051f9d9e9ee4c93a66bb147f4a77ab1406ac5b49ffffffffffffffffffffffffffffffffffffffffffffffcb3eef334cb7e0f5aea6c0affccb271ac4b5d07966a9a05cd6faffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a7ad4f304535eeb6c4b67b8241283117ef8e9a69015b9d2f2689bbbb22cbf31ef2008de411329ade1526269a1c4b2200fbaab0e97a0fdc6a07e7984bae7bb7583fac982544a65c5cefaac8af595696296b90c81d13b1d1494ee9226af211470087a58694b7ecbef528ffd59ccae6695b5dfc1e98819f2c6aa6052e8460e8c977067172455c627fe6c1a91e513effa2005033148bb0d630bf1c1d20d61933374474bcaad0744642644dcc1d54469b550433576ff35aab92382ac58e21a8473500",
    publicKeyMultibase: base64url.encode(
      concatBytes(BYTE_PRE_SQI_3, hexToBytes(pubkey3)),
    ),
  },
};

writeFile(baseDir + "KeysSQIsign.json", JSON.stringify(allKeys, null, 2));

