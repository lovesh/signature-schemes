use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use super::common::{Keypair, SigKey, VerKey};

pub struct Signature {
    pub point: G1,
}

impl Clone for Signature {
    fn clone(&self) -> Signature {
        Signature {
            point: self.point.clone(),
        }
    }
}

impl Signature {
    // Signature = H_0(msg) * sk
    pub fn new(msg: &[u8], sig_key: &SigKey) -> Self {
        let hash_point = G1::from_msg_hash(msg);
        let sig = hash_point * &sig_key.x;
        // This is different from the paper, the other exponentiation happens in aggregation.
        // This avoids the signer to know beforehand of all other participants
        Signature { point: sig }
    }

    pub fn verify(&self, msg: &[u8], ver_key: &VerKey) -> bool {
        // TODO: Check if point exists on curve, maybe use `ECP::new_big` and x cord of verkey
        if self.point.is_identity() {
            println!("Signature point at infinity");
            return false;
        }
        let msg_hash_point = G1::from_msg_hash(msg);
        let lhs = GT::ate_pairing(&self.point, &G2::generator());
        let rhs = GT::ate_pairing(&msg_hash_point, &ver_key.point);
        lhs == rhs
    }

    pub fn from_bytes(sig_bytes: &[u8]) -> Result<Signature, SerzDeserzError> {
        G1::from_bytes(sig_bytes).map(|point| Signature { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }
}

/*impl CurvePoint for Signature {
    fn is_valid_point(&self) -> bool {
        if self.point.is_infinity() {
            return false;
        }
        true
    }
}*/

#[cfg(test)]
mod tests {
    // TODO: Add tests for failure
    // TODO: Add more test vectors
    use super::*;

    #[test]
    fn sign_verify() {
        let keypair = Keypair::new(None);
        let sk = keypair.sig_key;
        let vk = keypair.ver_key;

        let msg = "Small msg";
        let msg1 = "121220888888822111212";
        let msg2 = "Some message to sign";
        let msg3 = "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222";
        for m in vec![msg, msg1, msg2, msg3] {
            let b = m.as_bytes();
            let mut sig = Signature::new(&b, &sk);
            assert!(sig.verify(&b, &vk));

            let bs = sig.to_bytes();
            let mut sig1 = Signature::from_bytes(&bs).unwrap();
            assert_eq!(&sig.point.to_hex(), &sig1.point.to_hex());
        }
    }

    #[test]
    fn verification_failure() {
        let keypair = Keypair::new(None);
        let sk = keypair.sig_key;
        let vk = keypair.ver_key;

        let mut msg = "Some msg";
        let sig = Signature::new(&msg.as_bytes(), &sk);
        msg = "Other msg";
        assert_eq!(sig.verify(&msg.as_bytes(), &vk), false);
        msg = "";
        assert_eq!(sig.verify(&msg.as_bytes(), &vk), false);
    }

    #[test]
    fn signature_at_infinity() {
        let keypair = Keypair::new(None);
        let vk = keypair.ver_key;

        let msg = "Small msg".as_bytes();
        let sig = Signature {
            point: G1::identity(),
        };
        assert_eq!(sig.verify(&msg, &vk), false);
    }
}
