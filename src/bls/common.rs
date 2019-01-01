extern crate amcl;
extern crate rand;

use rand::rngs::EntropyRng;
use super::amcl_utils::{random_big_number, hash_on_GroupG1, ate_pairing,
                        get_bytes_for_BigNum, get_bytes_for_G2_point, get_G2_point_from_bytes};
use super::types::{BigNum, GroupG1, GroupG2};
use super::constants::{CURVE_ORDER, GeneratorG2, GroupG2_SIZE, MODBYTES};
use bls::errors::SerzDeserzError;

pub struct SigKey {
    pub x: BigNum
}

impl SigKey {
    pub fn new(rng: Option<EntropyRng>) -> Self {
        SigKey {
            x: random_big_number(&CURVE_ORDER, rng),
        }
    }

    pub fn from_bytes(sk_bytes: &[u8]) -> Result<SigKey, SerzDeserzError> {
        if sk_bytes.len() != MODBYTES {
            return Err(SerzDeserzError::BigNumBytesIncorrectSize(sk_bytes.len(), MODBYTES))
        }
        Ok(SigKey {
            x: BigNum::frombytes(sk_bytes)
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        get_bytes_for_BigNum(&self.x)
    }
}

/* TryFrom is in unstable rust, use it when it becomes stable
impl From<Vec<u8>> for SigKey {
    fn from(vec: Vec<u8>) -> Self {
        SigKey {
            x: BigNum::frombytes(&vec)
        }
    }
}*/

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

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<VerKey, SerzDeserzError> {
        Ok(VerKey {
            point: get_G2_point_from_bytes(vk_bytes)?
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        get_bytes_for_G2_point(&self.point)
    }
}

/*impl From<Vec<u8>> for VerKey {
    fn from(vec: Vec<u8>) -> Self {
        VerKey {
            point: GroupG2::frombytes(&vec)
        }
    }
}

impl From<VerKey> for Vec<u8> {
    fn from(vk: VerKey) -> Self {
        vk.to_bytes()
    }
}*/

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

            /*let bs = vk1.to_bytes();
            let bs1 = bs.clone();
            let mut vk3 = VerKey::from(bs1);
            assert_eq!(&vk3.point.tostring(), &vk1.point.tostring());
            assert_eq!(&vk3.point.tostring(), &vk2.point.tostring());

            let mut sk_bytes: [u8; MODBYTES] = [0; MODBYTES];
            sk.x.tobytes(&mut sk_bytes);
            let mut s = SigKey::from(sk_bytes.to_vec());
            assert_eq!(&s.x.tostring(), &sk.x.tostring());

            let bs2: Vec<u8> = vk3.into();
            assert_eq!(bs, bs2);*/

            let bs = vk1.to_bytes();
            let mut vk11 = VerKey::from_bytes(&bs).unwrap();
            assert_eq!(&vk1.point.tostring(), &vk11.point.tostring());

            let bs = sk.to_bytes();
            let mut sk1 = SigKey::from_bytes(&bs).unwrap();
            assert_eq!(&sk1.x.tostring(), &sk.x.tostring());
        }
    }
}