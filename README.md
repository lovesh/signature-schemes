# Rust library for various signatures like Aggregate signatures, Multi signatures.
Uses the [The Apache Milagro Cryptographic Library](https://github.com/apache/incubator-milagro-crypto-rust)

## Supported schemes
1. BLS signatures from [Compact Multi-Signatures for Smaller Blockchains](https://eprint.iacr.org/2018/483.pdf) by Dan Boneh, Manu Drijvers and Gregory Neven.
   Used BLS12-381 curve from Apache Milagro. [Signing and verification API](./bls/README.md)
2. MuSig, Schnorr Multi-Signatures. [Simple Schnorr Multi-Signatures with Applications to Bitcoin](https://eprint.iacr.org/2018/068.pdf) 
by Gregory Maxwell and Andrew Poelstra and Yannick Seurin and Pieter Wuille. Used secp256k1 curve. [Signing and verification API](./musig/README.md)
3. [PS (Pointcheval Sanders) signatures](https://eprint.iacr.org/2015/525.pdf). 
