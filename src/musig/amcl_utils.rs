extern crate amcl;
extern crate rand;

use rand::RngCore;
use rand::rngs::EntropyRng;

use self::amcl::rand::{RAND};
use self::amcl::arch::Chunk;
use super::constants::MODBYTES;
use super::types::BigNum;
use super::super::utils::get_seeded_RNG;
use super::amcl::hash256::HASH256;


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