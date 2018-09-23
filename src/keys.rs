extern crate amcl;
extern crate rand;

use super::amcl_utils::{
    get_bytes_for_BigNum,
    get_bytes_for_G2_point,
    get_G2_point_from_bytes
};
use super::types::{
    BigNum,
    GroupG2
};
use super::constants::{
    CURVE_ORDER,
    GeneratorG2,
    MODBYTES
};
use super::rng::get_seeded_rng;
use super::errors::SerzDeserzError;

#[derive(Clone)]
pub struct SecretKey {
    pub x: BigNum
}

impl SecretKey {
    pub fn random() -> Self {
        let mut r = get_seeded_rng(256);
        let x = BigNum::randomnum(&BigNum::new_ints(&CURVE_ORDER), &mut r);
        SecretKey {
            x
        }
    }

    pub fn from_bytes(sk_bytes: &[u8])
        -> Result<SecretKey, SerzDeserzError>
    {
        if sk_bytes.len() != MODBYTES {
            return Err(SerzDeserzError::BigNumBytesIncorrectSize(sk_bytes.len(), MODBYTES))
        }
        Ok(SecretKey {
            x: BigNum::frombytes(sk_bytes)
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        get_bytes_for_BigNum(&self.x)
    }
}

pub struct PublicKey {
    pub point: GroupG2
}

impl Clone for PublicKey {
    fn clone(&self) -> PublicKey {
        let mut temp_v = GroupG2::new();
        temp_v.copy(&self.point);
        PublicKey {
            point: temp_v
        }
    }
}

impl PublicKey {
    pub fn from_sigkey(sk: &SecretKey) -> Self {
        PublicKey {
            point: GeneratorG2.mul(&sk.x),
        }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<PublicKey, SerzDeserzError> {
        Ok(PublicKey {
            point: get_G2_point_from_bytes(vk_bytes)?
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        get_bytes_for_G2_point(&self.point)
    }
}

#[derive(Clone)]
pub struct Keypair {
    pub sk: SecretKey,
    pub pk: PublicKey
}

impl Keypair {
    pub fn random() -> Self {
        let sk = SecretKey::random();
        let pk = PublicKey::from_sigkey(&sk);
        Keypair {
            sk,
            pk
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_verkey() {
        let sk1 = SecretKey::random();
        let sk2 = SecretKey::random();
        for mut sk in vec![sk1, sk2] {
            let mut vk1 = PublicKey::from_sigkey(&sk);

            let mut vk2 = PublicKey::from_sigkey(&sk);

            assert_eq!(&vk1.point.tostring(), &vk2.point.tostring());

            let bs = vk1.to_bytes();
            let mut vk11 = PublicKey::from_bytes(&bs).unwrap();
            assert_eq!(&vk1.point.tostring(), &vk11.point.tostring());

            let bs = sk.to_bytes();
            let mut sk1 = SecretKey::from_bytes(&bs).unwrap();
            assert_eq!(&sk1.x.tostring(), &sk.x.tostring());
        }
    }
}
