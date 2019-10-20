use rand::rngs::EntropyRng;

use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g2::G2;
use VerkeyGroup;

pub struct Params {
    pub g: VerkeyGroup,
}

impl Params {
    pub fn new(label: &[u8]) -> Self {
        // NUMS
        let g = VerkeyGroup::from_msg_hash(label);
        Params { g }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigKey {
    pub x: FieldElement,
}

impl SigKey {
    pub fn new(rng: Option<EntropyRng>) -> Self {
        match rng {
            Some(mut r) => SigKey {
                x: FieldElement::random_using_rng(&mut r),
            },
            None => SigKey {
                x: FieldElement::random(),
            },
        }
    }

    pub fn from_bytes(sk_bytes: &[u8]) -> Result<SigKey, SerzDeserzError> {
        FieldElement::from_bytes(sk_bytes).map(|x| SigKey { x })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.x.to_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerKey {
    pub point: VerkeyGroup,
}

impl VerKey {
    pub fn from_sigkey(sk: &SigKey, params: &Params) -> Self {
        VerKey {
            point: &params.g * &sk.x,
        }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<VerKey, SerzDeserzError> {
        VerkeyGroup::from_bytes(vk_bytes).map(|point| VerKey { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }
}

pub struct Keypair {
    pub sig_key: SigKey,
    pub ver_key: VerKey,
}

impl Keypair {
    pub fn new(rng: Option<EntropyRng>, params: &Params) -> Self {
        let sk = SigKey::new(rng);
        let vk = VerKey::from_sigkey(&sk, params);
        Keypair {
            sig_key: sk,
            ver_key: vk,
        }
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
        let params = Params::new("test".as_bytes());
        for mut sk in vec![sk1, sk2] {
            let mut vk1 = VerKey::from_sigkey(&sk, &params);
            debug!("{}", sk.x.to_hex());
            debug!("{}", &vk1.point.to_hex());

            let mut vk2 = VerKey::from_sigkey(&sk, &params);
            debug!("{}", &vk2.point.to_hex());

            //assert_eq!(&vk1.point.to_hex(), &vk2.point.to_hex());

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
            // FIXME: Next line fails
            //assert_eq!(&vk1.point.to_hex(), &vk11.point.to_hex());
            assert_eq!(vk1.point.to_bytes(), vk11.point.to_bytes());

            let bs = sk.to_bytes();
            let mut sk1 = SigKey::from_bytes(&bs).unwrap();
            assert_eq!(sk1.x.to_hex(), sk.x.to_hex());
        }
    }
}
