use rand::rngs::EntropyRng;
use rand::RngCore;

use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g2::G2;

pub struct SigKey {
    pub x: FieldElement
}

impl SigKey {
    pub fn new(rng: Option<EntropyRng>) -> Self {
        match rng {
            Some(mut r) => SigKey {
                x: FieldElement::random_using_rng(&mut r)
            },
            None => SigKey {
                x: FieldElement::random(),
            }
        }
    }

    pub fn from_bytes(sk_bytes: &[u8]) -> Result<SigKey, SerzDeserzError> {
        FieldElement::from_bytes(sk_bytes).map(|x| SigKey { x })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.x.to_bytes()
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
    pub point: G2
}

impl Clone for VerKey {
    fn clone(&self) -> VerKey {
        VerKey {
            point: self.point.clone()
        }
    }
}

impl VerKey {
    pub fn from_sigkey(sk: &SigKey) -> Self {
        VerKey {
            point: G2::generator() * sk.x,
        }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<VerKey, SerzDeserzError> {
        Ok(VerKey {
            point: G2::from_bytes(vk_bytes)?
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
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
            debug!("{}", sk.x.to_hex());
            debug!("{}", &vk1.point.to_hex());

            let mut vk2 = VerKey::from_sigkey(&sk);
            debug!("{}", &vk2.point.to_hex());

            assert_eq!(&vk1.point.to_hex(), &vk2.point.to_hex());

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
            assert_eq!(&vk1.point.to_hex(), &vk11.point.to_hex());

            let bs = sk.to_bytes();
            let mut sk1 = SigKey::from_bytes(&bs).unwrap();
            assert_eq!(&sk1.x.to_hex(), &sk.x.to_hex());
        }
    }
}