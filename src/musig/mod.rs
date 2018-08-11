extern crate amcl;
extern crate rand;

pub mod musig;
pub mod types;
pub mod constants;
mod amcl_utils;

pub use self::amcl::secp256k1 as SchnorrCurve;