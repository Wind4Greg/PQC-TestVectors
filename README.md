# Test Vector Generation for Quantum Safe Data Integrity

## Generic Functions

General Non-SD approach

1. High Level Algorithms (would write for each signature type, e.g., ML-DSA, SLH-DSA but not each flavor)
   1. **Create Proof(signature and parameters)**
   2. **Verify Proof (signature and parameters)**

2. General Functions used by Create and Verify Proof
   1. Transformation (unsecured document, *rdfc* or *jcs*) returns  canonicalDocument
   2. Hashing (transformedDocument, canonicalProofConfig, hash function) returns hashData
   3. Proof Configuration (proofOptions, *rdfc* or *jcs*) returns canonicalProofConfig
   4. Proof Serialization (hashData, signature algorithm and parameters, private key) returns proofBytes
   5. Proof Verification (public key, hashData, signature algorithm and parameters) returns verificationResult