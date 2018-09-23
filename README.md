# Rust library for various signatures like Aggregate signatures, Multi signatures.
Uses the [The Apache Milagro Cryptographic Library](https://github.com/milagro-crypto/amcl)

## Supported schemes
1. BLS signatures from [Compact Multi-Signatures for Smaller Blockchains](https://eprint.iacr.org/2018/483.pdf) by Dan Boneh, Manu Drijvers and Gregory Neven.
   Used BLS12-381 curve from Apache Milagro. [Signing and verification API](./src/bls/README.md)
