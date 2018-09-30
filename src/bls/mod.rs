// BLS Signatures.
// From: "Dan Boneh, Manu Drijvers, Gregory Neven. Compact Multi-Signatures for Smaller Blockchains".
// Available from: https://eprint.iacr.org/2018/483.pdf
// This link was helpful too https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html

// TODO: Add domain separation, for single sig, aggregation sig
// TODO: Add From and Into traits for converting from and to bytes for various structs
// TODO: Support point compression

extern crate amcl;
extern crate rand;

pub mod common;
pub mod simple;
pub mod aggr_slow;
pub mod aggr_fast;
pub mod types;
pub mod constants;
pub mod errors;
pub mod amcl_utils;

// Change self::amcl::bls381 to self::amcl::bls383 to use BLS383 curve
pub use self::amcl::bls381 as BLSCurve;