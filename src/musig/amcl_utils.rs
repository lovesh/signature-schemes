extern crate amcl;
extern crate rand;

use rand::RngCore;
use rand::rngs::EntropyRng;

use self::amcl::rand::{RAND};
use self::amcl::arch::Chunk;
use super::constants::{MODBYTES, GroupG_Size};
use super::types::{BigNum, GroupG};
use super::super::utils::get_seeded_RNG;
use super::amcl::hash256::HASH256;
use musig::errors::SerzDeserzError;


pub fn random_big_number(order: &[Chunk], rng: Option<EntropyRng>) -> BigNum {
    // initialise from at least 128 byte string of raw random entropy
    let entropy_size = 256;
    let mut r = get_seeded_RNG(entropy_size, rng);
    BigNum::randomnum(&BigNum::new_ints(&order), &mut r)
}

pub fn hash_as_BigNum(msg: &[u8]) -> BigNum {
    let mut h: [u8; MODBYTES] = [0; MODBYTES];
    let mut sh = HASH256::new();
    for i in 0..msg.len(){
        sh.process(msg[i]);
    }
    let digest = sh.hash();
    let digest_len = digest.len();
    if digest_len > MODBYTES {
        for i in 0..MODBYTES {h[i] = digest[i];}
    } else {
        for i in 0..digest_len {h[i] = digest[i];}
        // Add padding
        for i in digest_len..MODBYTES {h[i] = 0;}
    }
    BigNum::frombytes(&h)
}

pub fn get_bytes_for_BigNum(n: &BigNum) -> Vec<u8> {
    let mut temp = BigNum::new_copy(&n);
    let mut bytes: [u8; MODBYTES] = [0; MODBYTES];
    temp.tobytes(&mut bytes);
    bytes.to_vec()
}

pub fn get_BigNum_from_bytes(bytes: &[u8]) -> Result<BigNum, SerzDeserzError> {
    if bytes.len() != MODBYTES {
        return Err(SerzDeserzError::BigNumBytesIncorrectSize(bytes.len(), MODBYTES))
    }
    Ok(BigNum::frombytes(bytes))
}

pub fn get_bytes_for_GroupG_point(point: &GroupG) -> Vec<u8> {
    let mut temp = GroupG::new();
    temp.copy(point);
    let mut bytes: [u8; GroupG_Size] = [0; GroupG_Size];
    temp.tobytes(&mut bytes, false);
    bytes.to_vec()
}

pub fn get_GroupG_point_from_bytes(bytes: &[u8]) -> Result<GroupG, SerzDeserzError> {
    if bytes.len() != GroupG_Size {
        return Err(SerzDeserzError::GroupG2BytesIncorrectSize(bytes.len(), GroupG_Size))
    }
    Ok(GroupG::frombytes(bytes))
}