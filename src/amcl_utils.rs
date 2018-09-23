extern crate amcl;
extern crate rand;

use BLSCurve::mpin::{SHA256, hash_id};
use BLSCurve::pair::{ate, fexp};
use super::types::{
    GroupG1,
    GroupG2,
    FP12
};
use super::constants::MOD_BYTE_SIZE;

pub fn hash_on_g1(msg: &[u8]) -> GroupG1 {
    let mut h: [u8; MOD_BYTE_SIZE] = [0; MOD_BYTE_SIZE];
    hash_id(SHA256, msg, &mut h);
    GroupG1::mapit(&h)
}

pub fn ate_pairing(point_g2: &GroupG2, point_g1: &GroupG1) -> FP12 {
    let e = ate(&point_g2, &point_g1);
    fexp(&e)
}
