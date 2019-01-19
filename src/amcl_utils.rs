extern crate amcl;
extern crate rand;
extern crate blake2_rfc;

use self::blake2_rfc::blake2b::blake2b;
use BLSCurve::pair::{ate, fexp};
use self::amcl::arch::Chunk;
use BLSCurve::rom;
use BLSCurve::big::{NLEN, MODBYTES as bls381_MODBYTES};
use BLSCurve::big::BIG;
use BLSCurve::ecp::ECP;
use BLSCurve::ecp2::ECP2;
use BLSCurve::fp12::FP12 as bls381_FP12;

pub type BigNum = BIG;
pub type GroupG1 = ECP;
pub type GroupG2 = ECP2;
pub type FP12 = bls381_FP12;

pub const CURVE_ORDER: [Chunk; NLEN] = rom::CURVE_ORDER;
pub const MODBYTES: usize = bls381_MODBYTES;

// Byte size of element in group G1, 1 extra byte for compression
pub const G1_BYTE_SIZE: usize = (2 * MODBYTES + 1) as usize;
// Byte size of element in group G2
pub const G2_BYTE_SIZE: usize = (4 * MODBYTES) as usize;
// Byte size of secret key
pub const MOD_BYTE_SIZE: usize = bls381_MODBYTES;

lazy_static! {
    pub static ref GeneratorG1: GroupG1 = GroupG1::generator();
    pub static ref GeneratorG2: GroupG2 = GroupG2::generator();
}

pub fn hash_on_g1(msg: &[u8], d: u64) -> GroupG1 {
    let result = blake2b(49, &[], &[msg, &d.to_be_bytes()].concat());
    GroupG1::mapit(&result.as_bytes())
}

pub fn map_to_g1(val: &[u8]) -> GroupG1 {
    GroupG1::mapit(val)
}

pub fn ate_pairing(point_g2: &GroupG2, point_g1: &GroupG1) -> FP12 {
    let e = ate(&point_g2, &point_g1);
    fexp(&e)
}
