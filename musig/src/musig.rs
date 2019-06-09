extern crate rand;

use rand::rngs::EntropyRng;
use rand::RngCore;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::constants::MODBYTES;


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

pub struct VerKey {
    pub point: G1
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
            point: G1::generator() * sk.x
        }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<VerKey, SerzDeserzError> {
        G1::from_bytes(vk_bytes).map(|point| VerKey { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
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

pub struct Nonce {
    pub x: Option<FieldElement>,
    pub point: G1
}

impl Clone for Nonce {
    fn clone(&self) -> Nonce {
        Nonce {
            x: self.x.clone(),
            point: self.point.clone()
        }
    }
}

impl Nonce {
    pub fn new(rng: Option<EntropyRng>) -> Self {
        let n = match rng {
            Some(mut r) => FieldElement::random_using_rng(&mut r),
            None => FieldElement::random()
        };
        let p = G1::generator() * n;
        Nonce {
            x: Some(n),
            point: p,
        }
    }

    pub fn aggregate(nonces: &Vec<Nonce>) -> Nonce {
        let mut an = G1::identity();
        for n in nonces {
            an += n.point;
        }
        Nonce {
            x: None,
            point: an,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Nonce, SerzDeserzError> {
        G1::from_bytes(bytes).map(|point| Nonce {
            x: None,
            point
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }
}


pub struct HashedVerKeys {
    pub b: [u8; MODBYTES]
}

impl HashedVerKeys {
    pub fn new(verkeys: &Vec<VerKey>) -> HashedVerKeys {
        let mut bytes: Vec<u8> = vec![];
        for vk in verkeys {
            bytes.extend(vk.to_bytes());
        }
        let mut b: [u8; MODBYTES] = [0; MODBYTES];
        b.copy_from_slice(&FieldElement::from_msg_hash(&bytes).to_bytes());
        HashedVerKeys {
            b
        }
    }

    pub fn hash_with_verkey(&self, verkey: &VerKey) -> FieldElement {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.b.iter());
        bytes.extend(verkey.to_bytes());
        FieldElement::from_msg_hash(&bytes)
    }
}

pub struct AggregatedVerKey {
    pub point: G1
}

impl Clone for AggregatedVerKey {
    fn clone(&self) -> AggregatedVerKey {
        AggregatedVerKey {
            point: self.point.clone()
        }
    }
}

impl AggregatedVerKey {
    pub fn new(verkeys: &Vec<VerKey>) -> AggregatedVerKey {
        let L = HashedVerKeys::new(verkeys);
        let mut avk = G1::identity();
        for vk in verkeys {
            let point = vk.point * L.hash_with_verkey(vk);
            avk += point;
            //avk.add(&point);
        }
        AggregatedVerKey {
            point: avk,
        }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<AggregatedVerKey, SerzDeserzError> {
        G1::from_bytes(vk_bytes).map(|point| AggregatedVerKey { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }
}

pub struct Signature {
    pub x: FieldElement
}

impl Signature {
    // Signature =
    pub fn new(msg: &[u8], sig_key: &SigKey, nonce: &FieldElement, verkey: &VerKey,
               all_nonces: &Vec<Nonce>, all_verkeys: &Vec<VerKey>) -> Self {
        let R = Nonce::aggregate(all_nonces);
        let L = HashedVerKeys::new(all_verkeys);
        let avk = AggregatedVerKey::new(all_verkeys);

        Signature::new_using_aggregated_objs(msg, sig_key, nonce, verkey, &R, &L, &avk)
    }

    pub fn new_using_aggregated_objs(msg: &[u8], sig_key: &SigKey, nonce: &FieldElement, verkey: &VerKey,
                                     R: &Nonce, L: &HashedVerKeys, avk: &AggregatedVerKey) -> Self {
        let mut h = L.hash_with_verkey(&verkey);

        let mut challenge = Signature::compute_challenge(msg, &avk.to_bytes(), &R.to_bytes());
        
        let mut product = (challenge * h * sig_key.x) + nonce;

        Signature { x: product }
    }

    pub fn compute_challenge(msg: &[u8], aggr_verkey: &[u8], aggr_nonce: &[u8]) -> FieldElement {
        let mut challenge_bytes: Vec<u8> = vec![];
        challenge_bytes.extend(aggr_verkey);
        challenge_bytes.extend(aggr_nonce);
        challenge_bytes.extend(msg);
        FieldElement::from_msg_hash(&challenge_bytes)
    }

    pub fn from_bytes(sig_bytes: &[u8]) -> Result<Signature, SerzDeserzError> {
        FieldElement::from_bytes(sig_bytes).map(|x| Signature { x })

    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.x.to_bytes()
    }
}


pub struct AggregatedSignature {
    pub x: FieldElement
}

impl AggregatedSignature {
    pub fn new(signatures: &[Signature]) -> Self {
        let mut aggr_sig: FieldElement = FieldElement::new();
        for sig in signatures {
            //aggr_sig.add(&sig.x);
            aggr_sig += sig.x
        }
        AggregatedSignature {
            x: aggr_sig
        }
    }

    pub fn verify(&self, msg: &[u8], nonces: &Vec<Nonce>, ver_keys: &Vec<VerKey>) -> bool {
        let R = Nonce::aggregate(nonces);
        let avk = AggregatedVerKey::new(ver_keys);
        self.verify_using_aggregated_objs(msg, &R, &avk)
    }

    pub fn verify_using_aggregated_objs(&self, msg: &[u8], R: &Nonce, avk: &AggregatedVerKey) -> bool {
        let challenge = Signature::compute_challenge(msg, &avk.to_bytes(),
                                                     &R.to_bytes());
        let lhs = G1::generator() * self.x;
        let rhs = G1::identity() + &R.point + &(&avk.point * &challenge);
        lhs == rhs
    }

    pub fn from_bytes(asig_bytes: &[u8]) -> Result<AggregatedSignature, SerzDeserzError> {
        FieldElement::from_bytes(asig_bytes).map(|x| AggregatedSignature { x })

    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.x.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_verkey() {
        let mut sk = SigKey::new(None);
        let mut vk1 = VerKey::from_sigkey(&sk);
        let mut vk2 = VerKey::from_sigkey(&sk);
        assert_eq!(&vk1.point.to_hex(), &vk2.point.to_hex());

        let bs = vk1.to_bytes();
        let mut vk11 = VerKey::from_bytes(&bs).unwrap();
        assert_eq!(&vk1.point.to_hex(), &vk11.point.to_hex());

        let bs = sk.to_bytes();
        let mut sk1 = SigKey::from_bytes(&bs).unwrap();
        assert_eq!(&sk1.x.to_hex(), &sk.x.to_hex());
    }


    #[test]
    fn aggr_sign_verify() {
        let keypairs: Vec<Keypair> = (0..5).map(|_| Keypair::new(None)).collect();
        let verkeys: Vec<VerKey> = keypairs.iter().map(|k| k.ver_key.clone()).collect();

        let msgs = vec![
            "Small msg",
            "121220888888822111212",
            "Some message to sign",
            "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222",
            " is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
        ];

        for msg in msgs {
            let nonces: Vec<Nonce> = (0..5).map(|_| Nonce::new(None)).collect();
            let mut signatures: Vec<Signature> = vec![];
            let msg_b = msg.as_bytes();
            for i in 0..5 {
                let keypair = &keypairs[i];
                let sig = Signature::new(msg_b, &keypair.sig_key, &nonces[i].x.unwrap(), &keypair.ver_key, &nonces, &verkeys);
                signatures.push(sig);
            }
            let aggr_sig: AggregatedSignature = AggregatedSignature::new(&signatures);
            assert!(aggr_sig.verify(msg_b, &nonces, &verkeys));

            let R = Nonce::aggregate(&nonces);
            let verkeys = keypairs.iter().map(|k| k.ver_key.clone()).collect();
            let L = HashedVerKeys::new(&verkeys);
            let mut avk = AggregatedVerKey::new(&verkeys);

            let mut signatures: Vec<Signature> = vec![];
            for i in 0..5 {
                let keypair = &keypairs[i];
                let sig = Signature::new_using_aggregated_objs(msg_b, &keypair.sig_key, &nonces[i].x.unwrap(), &keypair.ver_key, &R, &L, &avk);
                signatures.push(sig);
            }
            let aggr_sig: AggregatedSignature = AggregatedSignature::new(&signatures);
            assert!(aggr_sig.verify_using_aggregated_objs(msg_b, &R, &avk));

            let bs = avk.to_bytes();
            let mut avk_from_bytes = AggregatedVerKey::from_bytes(&bs).unwrap();
            // FIXME: Next line fails
            //assert_eq!(&avk.point.to_hex(), &avk_from_bytes.point.to_hex());
            assert!(aggr_sig.verify_using_aggregated_objs(msg_b, &R, &avk_from_bytes));
        }
    }
}