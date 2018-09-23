extern crate amcl;

use super::amcl_utils::{
    hash_on_g1,
    ate_pairing,
    GeneratorG2,
};
use super::keys::{
    SecretKey,
    PublicKey,
};
use super::g1::G1Point;
use super::errors::DecodeError;

#[derive(Debug, Clone)]
pub struct Signature {
    pub point: G1Point,
}

impl Signature {
    pub fn new(msg: &[u8], sk: &SecretKey) -> Self {
        let hash_point = hash_on_g1(msg);
        let sig = hash_point.mul(&sk.x);
        Self {
            point: G1Point::from_raw(sig)
        }
    }

    pub fn verify(&self, msg: &[u8], pk: &PublicKey) -> bool {
        // TODO: Check if point exists on curve, maybe use `ECP::new_big`
        // and x cord of verkey
        if self.point.is_infinity() {
            return false;
        }
        let msg_hash_point = hash_on_g1(msg);
        let mut lhs = ate_pairing(&GeneratorG2, self.point.as_raw());
        let mut rhs = ate_pairing(&pk.point.as_raw(), &msg_hash_point);
        lhs.equals(&mut rhs)
    }

    pub fn from_bytes(bytes: &[u8])
        -> Result<Signature, DecodeError>
    {
        let point = G1Point::from_bytes(bytes)?;
        Ok(Self{ point })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.point.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::keys::Keypair;

    #[test]
    fn basic_sign_verify() {
        let keypair = Keypair::random();
        let sk = keypair.sk;
        let vk = keypair.pk;

        let messages = vec![
            "",
            "a",
            "an example",
        ];

        for m in messages {
            /*
             * Simple sign and verify
             */
            let bytes = m.as_bytes();
            let mut sig = Signature::new(&bytes, &sk);
            assert!(sig.verify(&bytes, &vk));

            /*
             * Test serializing, then deserializing the signature
             */
            let sig_bytes = sig.as_bytes();
            let mut new_sig = Signature::from_bytes(&sig_bytes).unwrap();
            assert_eq!(&sig.as_bytes(), &new_sig.as_bytes());
            assert!(new_sig.verify(&bytes, &vk));
        }
    }

    #[test]
    fn verification_failure() {
        let keypair = Keypair::random();
        let sk = keypair.sk;
        let vk = keypair.pk;

        let mut msg = "Some msg";
        let sig = Signature::new(&msg.as_bytes(), &sk);
        msg = "Other msg";
        assert_eq!(sig.verify(&msg.as_bytes(), &vk), false);
        msg = "";
        assert_eq!(sig.verify(&msg.as_bytes(), &vk), false);
    }
}
