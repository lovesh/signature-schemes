#![allow(non_snake_case)]

// BLS Signatures.
// From: "Dan Boneh, Manu Drijvers, Gregory Neven. Compact Multi-Signatures for Smaller Blockchains".
// Available from: https://eprint.iacr.org/2018/483.pdf
// This link was helpful too https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html

// TODO: Add domain separation, for single sig, aggregation sig
// TODO: Add From and Into traits for converting from and to bytes for various structs
// TODO: Support point compression

extern crate amcl_wrapper;
extern crate rand;

use amcl_wrapper::extension_field_gt::GT;

#[cfg(all(feature = "SignatureG1", feature = "SignatureG2"))]
compile_error!("features `SignatureG1` and `SignatureG2` are mutually exclusive");

// For feature SignatureG1, signature and message are in G1, verification key in G2
#[cfg(feature = "SignatureG1")]
pub type SignatureGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "SignatureG1")]
pub type SignatureGroupVec = amcl_wrapper::group_elem_g1::G1Vector;
#[cfg(feature = "SignatureG1")]
pub type VerkeyGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "SignatureG1")]
pub type VerkeyGroupVec = amcl_wrapper::group_elem_g2::G2Vector;
#[cfg(feature = "SignatureG1")]
pub fn ate_2_pairing(
    g1: &SignatureGroup,
    g2: &VerkeyGroup,
    h1: &SignatureGroup,
    h2: &VerkeyGroup,
) -> GT {
    GT::ate_2_pairing(g1, g2, h1, h2)
}

// For feature SignatureG2, signature and message are in G2, verification key in G1
#[cfg(feature = "SignatureG2")]
pub type SignatureGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "SignatureG2")]
pub type SignatureGroupVec = amcl_wrapper::group_elem_g2::G2Vector;
#[cfg(feature = "SignatureG2")]
pub type VerkeyGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "SignatureG2")]
pub type VerkeyGroupVec = amcl_wrapper::group_elem_g1::G1Vector;
#[cfg(feature = "SignatureG2")]
pub fn ate_2_pairing(
    g1: &SignatureGroup,
    g2: &VerkeyGroup,
    h1: &SignatureGroup,
    h2: &VerkeyGroup,
) -> GT {
    GT::ate_2_pairing(g2, g1, h2, h1)
}

#[cfg(test)]
#[macro_use]
extern crate log;

extern crate serde;
#[macro_use]
extern crate serde_derive;

extern crate secret_sharing;

pub mod common;
pub mod multi_sig_fast;
pub mod multi_sig_slow;
pub mod simple;
pub mod threshold_sig;
