extern crate amcl;
extern crate rand;

use rand::RngCore;
use rand::rngs::EntropyRng;

use self::amcl::rand::{RAND};
use self::amcl::arch::Chunk;
use BLSCurve::mpin::{SHA384, hash_id};
use BLSCurve::pair::{ate, fexp};
use super::types::{BigNum, GroupG1, GroupG2, FP12};
use super::super::utils::get_seeded_RNG;
use bls::constants::{GroupG2_SIZE, GroupG1_SIZE, MODBYTES};
use bls::errors::SerzDeserzError;

pub fn random_big_number(order: &[Chunk], rng: Option<EntropyRng>) -> BigNum {
    // initialise from at least 128 byte string of raw random entropy
    let entropy_size = 256;
    let mut r = get_seeded_RNG(entropy_size, rng);
    BigNum::randomnum(&BigNum::new_ints(&order), &mut r)
}


pub fn hash_on_GroupG1(msg: &[u8]) -> GroupG1 {
    let mut h: [u8; MODBYTES] = [0; MODBYTES];
    hash_id(SHA384, msg, &mut h);
    GroupG1::mapit(&h)
}

pub fn hash_on_GroupG2(msg: &[u8]) -> GroupG2 {
    let mut h: [u8; MODBYTES] = [0; MODBYTES];
    hash_id(SHA384, msg, &mut h);
    GroupG2::mapit(&h)
}

pub fn hash_as_BigNum(msg: &[u8]) -> BigNum {
    let mut h: [u8; MODBYTES] = [0; MODBYTES];
    hash_id(SHA384, msg, &mut h);
    BigNum::frombytes(&h)
}

pub fn ate_pairing(point_G2: &GroupG2, point_G1: &GroupG1) -> FP12 {
    let e = ate(&point_G2, &point_G1);
    fexp(&e)
}

pub fn get_bytes_for_G1_point(point: &GroupG1) -> Vec<u8> {
    let mut temp = GroupG1::new();
    temp.copy(point);
    let mut bytes: [u8; GroupG1_SIZE] = [0; GroupG1_SIZE];
    temp.tobytes(&mut bytes, false);
    bytes.to_vec()
}

pub fn get_G1_point_from_bytes(bytes: &[u8]) -> Result<GroupG1, SerzDeserzError> {
    if bytes.len() != GroupG1_SIZE {
        return Err(SerzDeserzError::GroupG2BytesIncorrectSize(bytes.len(), GroupG1_SIZE))
    }
    Ok(GroupG1::frombytes(bytes))
}

pub fn get_bytes_for_G2_point(point: &GroupG2) -> Vec<u8> {
    let mut temp = GroupG2::new();
    temp.copy(point);
    let mut bytes: [u8; GroupG2_SIZE] = [0; GroupG2_SIZE];
    temp.tobytes(&mut bytes);
    bytes.to_vec()
}

pub fn get_G2_point_from_bytes(bytes: &[u8]) -> Result<GroupG2, SerzDeserzError> {
    if bytes.len() != GroupG2_SIZE {
        return Err(SerzDeserzError::GroupG2BytesIncorrectSize(bytes.len(), GroupG2_SIZE))
    }
    Ok(GroupG2::frombytes(bytes))
}

pub fn get_bytes_for_BigNum(n: &BigNum) -> Vec<u8> {
    let mut temp = BigNum::new_copy(&n);
    let mut bytes: [u8; MODBYTES] = [0; MODBYTES];
    temp.tobytes(&mut bytes);
    bytes.to_vec()
}

// TODO: impl From and To bytes traits

/*
pub struct CurvePoint<G> {
    pub point: G
}

impl<G> CurvePoint<G> {
    fn is_valid_point(&self) -> bool {
        if self.point.is_infinity() {
            return false;
        }
        true
    }
}


enum CP {
    G1(GroupG1),
    G2(GroupG2),
}

impl CP {
    fn is_valid_point(&self) -> bool {
        match self {
            G1(g1) =>  {
                !g1.point.is_infinity()
            },
            G2(g2) =>  {
                !g2.point.is_infinity()
            }
        }
        if self.point.is_infinity() {
            return false;
        }
        true
    }
}*/
