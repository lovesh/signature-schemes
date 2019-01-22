extern crate amcl;
#[macro_use]
extern crate lazy_static;
extern crate rand;

mod aggregates;
mod amcl_utils;
mod errors;
mod g1;
mod g2;
mod keys;
mod rng;
mod signature;

use self::amcl::bls381 as BLSCurve;

pub use aggregates::{AggregatePublicKey, AggregateSignature};
pub use errors::DecodeError;
pub use keys::{Keypair, PublicKey, SecretKey};
pub use signature::Signature;
