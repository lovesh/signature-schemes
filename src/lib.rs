extern crate amcl;
extern crate rand;

mod keys;
mod signature;
mod aggregates;
mod types;
mod constants;
mod errors;
mod amcl_utils;
mod rng;

use self::amcl::bls381 as BLSCurve;

pub use aggregates::{
    AggregateSignature,
    AggregatePublicKey,
};

#[macro_use]
extern crate lazy_static;
