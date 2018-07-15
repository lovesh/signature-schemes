extern crate amcl;
extern crate rand;

use rand::rngs::EntropyRng;
use super::amcl_utils::{random_big_number, hash_as_BigNum};
use super::types::{BigNum, GroupG};
use super::constants::{CURVE_ORDER, GeneratorG, GroupG_Size};

pub struct SigKey {
    pub x: BigNum
}

impl SigKey {
    pub fn new(rng: Option<EntropyRng>) -> Self {
        SigKey {
            x: random_big_number(&CURVE_ORDER, rng),
        }
    }
}

pub struct VerKey {
    pub point: GroupG
}

impl Clone for VerKey {
    fn clone(&self) -> VerKey {
        let mut temp_v = GroupG::new();
        temp_v.copy(&self.point);
        VerKey {
            point: temp_v
        }
    }
}

impl VerKey {
    pub fn from_sigkey(sk: &SigKey) -> Self {
        VerKey {
            point: GeneratorG.mul(&sk.x),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vk_clone = self.clone();
        let mut vk_bytes: [u8; GroupG_Size] = [0; GroupG_Size];
        vk_clone.point.tobytes(&mut vk_bytes, false);
        vk_bytes.to_vec()
    }
}