extern crate amcl;

use BLSCurve::big::BIG;
use BLSCurve::ecp::ECP;
use BLSCurve::ecp2::ECP2;
use BLSCurve::fp12::FP12 as bls381_FP12;

pub type BigNum = BIG;
pub type GroupG1 = ECP;
pub type GroupG2 = ECP2;
pub type FP12 = bls381_FP12;
