extern crate amcl;
extern crate rand;

use rand::rngs::EntropyRng;
use super::amcl_utils::{random_big_number, hash_on_GroupG1, ate_pairing, hash_as_BigNum};
use super::types::{BigNum, GroupG1, GroupG2};
use super::constants::{CURVE_ORDER, GeneratorG2, GroupG2_SIZE};

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
    pub point: GroupG2
}

impl Clone for VerKey {
    fn clone(&self) -> VerKey {
        let mut temp_v = GroupG2::new();
        temp_v.copy(&self.point);
        VerKey {
            point: temp_v
        }
    }
}

impl VerKey {
    pub fn from_sigkey(sk: &SigKey) -> Self {
        VerKey {
            point: GeneratorG2.mul(&sk.x),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vk_clone = self.clone();
        let mut vk_bytes: [u8; GroupG2_SIZE] = [0; GroupG2_SIZE];
        vk_clone.point.tobytes(&mut vk_bytes);
        vk_bytes.to_vec()
    }
}

pub struct Keypair {
    pub sig_key: SigKey,
    pub ver_key: VerKey
}

impl Keypair {
    pub fn new(rng: Option<EntropyRng>) -> Self {
        let sk = SigKey::new(rng);
        let vk = VerKey::from_sigkey(&sk);
        Keypair { sig_key: sk, ver_key: vk }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_verkey() {
        let sk1 = SigKey::new(None);
        let rng = EntropyRng::new();
        let sk2 = SigKey::new(Some(rng));
        for mut sk in vec![sk1, sk2] {
            let mut vk1 = VerKey::from_sigkey(&sk);
            debug!("{}", sk.x.tostring());
            debug!("{}", &vk1.point.tostring());

            let mut vk2 = VerKey::from_sigkey(&sk);
            debug!("{}", &vk2.point.tostring());

            assert_eq!(&vk1.point.tostring(), &vk2.point.tostring());
        }
    }
}