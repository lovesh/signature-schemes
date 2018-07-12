extern crate amcl;

use self::amcl::bls381::big::BIG;
use self::amcl::bls381::ecp::ECP;
use self::amcl::bls381::ecp2::ECP2;
use self::amcl::bls381::fp12::FP12 as bls381_FP12;

pub type BigNum = BIG;
pub type GroupG1 = ECP;
pub type GroupG2 = ECP2;
pub type FP12 = bls381_FP12;
