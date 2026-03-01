# Test Vector Generation for Quantum Safe Data Integrity

This repository contains code to generate test vectors for the [Quantum-Safe Cryptosuites](https://w3c-ccg.github.io/di-quantum-safe/) Draft Community Report.

## Use

After cloning this repo and running `npm install`. You can then must run one of the XCreate.js files prior to running the corresponding XVerify.js file. Test vectors will be place in a `./output` directory.

## Generic Functions

To reduce the number of test vectors for reasonable coverage we will use the functional refactoring suggested in [di-quantum-safe Issue #9](https://github.com/w3c-ccg/di-quantum-safe/issues/9).

Note: This is early in the development cycle.

1. High Level Algorithms (would write for each signature type, e.g., ML-DSA, SLH-DSA but not each flavor)
   1. **Create Proof(signature and parameters)**
      1. Proof Configuration
      2. Transformation
      3. Hashing
      4. Proof Serialization
   2. **Verify Proof (signature and parameters)**
      1. Proof Configuration
      2. Transformation
      3. Hashing
      4. Proof Verification

2. General Functions used by Create and Verify Proof
   1. Transformation (unsecured document, *rdfc* or *jcs*) returns  canonicalDocument
   2. Hashing (transformedDocument, canonicalProofConfig, hash function) returns hashData
   3. Proof Configuration (proofOptions, *rdfc* or *jcs*) returns canonicalProofConfig
   4. Proof Serialization (hashData, signature algorithm and parameters, private key) returns proofBytes
   5. Proof Verification (public key, hashData, signature algorithm and parameters) returns verificationResult.
