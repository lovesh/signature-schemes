extern crate amcl;
#[macro_use]
extern crate lazy_static;
extern crate rand;

mod keys;
mod signature;
mod aggregates;
mod errors;
mod g1;
mod amcl_utils;
mod rng;

use self::amcl::bls381 as BLSCurve;

pub use aggregates::{
    AggregateSignature,
    AggregatePublicKey,
};
pub use keys::{
    SecretKey,
    PublicKey,
    Keypair,
};
pub use signature::Signature;
pub use errors::DecodeError;
