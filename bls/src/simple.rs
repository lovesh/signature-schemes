use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use super::common::{SigKey, VerKey};
use common::Params;
use {ate_2_pairing, SignatureGroup};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub point: SignatureGroup,
}

impl Signature {
    // Signature = H_0(msg) * sk
    pub fn new(msg: &[u8], sig_key: &SigKey) -> Self {
        let hash_point = SignatureGroup::from_msg_hash(msg);
        let sig = hash_point * &sig_key.x;
        // This is different from the paper, the other exponentiation happens in aggregation.
        // This avoids the signer to know beforehand of all other participants
        Signature { point: sig }
    }

    pub fn verify(&self, msg: &[u8], ver_key: &VerKey, params: &Params) -> bool {
        // TODO: Check if point exists on curve, maybe use `ECP::new_big` and x cord of verkey
        if self.point.is_identity() {
            println!("Signature point at infinity");
            return false;
        }
        let msg_hash_point = SignatureGroup::from_msg_hash(msg);
        // e(self.point, params.g) == e(msg_hash_point, ver_key.point) =>
        // e(msg_hash_point, ver_key.point) * e(self.point, params.g)^-1 == 1 =>
        // e(msg_hash_point, ver_key.point) * e(self.point, params.g^-1) == 1
        ate_2_pairing(
            &msg_hash_point,
            &ver_key.point,
            &self.point,
            &params.g.negation(),
        )
        .is_one()
    }

    pub fn from_bytes(sig_bytes: &[u8]) -> Result<Signature, SerzDeserzError> {
        SignatureGroup::from_bytes(sig_bytes).map(|point| Signature { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    // TODO: Add tests for failure
    // TODO: Add more test vectors
    use super::*;
    use crate::common::Keypair;

    #[test]
    fn sign_verify() {
        let params = Params::new("test".as_bytes());
        let keypair = Keypair::new(None, &params);
        let sk = keypair.sig_key;
        let vk = keypair.ver_key;

        let msg = "Small msg";
        let msg1 = "121220888888822111212";
        let msg2 = "Some message to sign";
        let msg3 = "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222";
        for m in vec![msg, msg1, msg2, msg3] {
            let b = m.as_bytes();
            let mut sig = Signature::new(&b, &sk);
            assert!(sig.verify(&b, &vk, &params));

            let bs = sig.to_bytes();
            let mut sig1 = Signature::from_bytes(&bs).unwrap();
            // FIXME: Next line fails
            //assert_eq!(&sig.point.to_hex(), &sig1.point.to_hex());
            assert_eq!(&sig.point.to_bytes(), &sig1.point.to_bytes());
        }
    }

    #[test]
    fn verification_failure() {
        let params = Params::new("test".as_bytes());
        let keypair = Keypair::new(None, &params);
        let sk = keypair.sig_key;
        let vk = keypair.ver_key;

        let mut msg = "Some msg";
        let sig = Signature::new(&msg.as_bytes(), &sk);
        msg = "Other msg";
        assert_eq!(sig.verify(&msg.as_bytes(), &vk, &params), false);
        msg = "";
        assert_eq!(sig.verify(&msg.as_bytes(), &vk, &params), false);
    }

    #[test]
    fn signature_at_infinity() {
        let params = Params::new("test".as_bytes());
        let keypair = Keypair::new(None, &params);
        let vk = keypair.ver_key;

        let msg = "Small msg".as_bytes();
        let sig = Signature {
            point: SignatureGroup::identity(),
        };
        assert_eq!(sig.verify(&msg, &vk, &params), false);
    }
}
