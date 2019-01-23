extern crate amcl;

use super::amcl_utils::{ate_pairing, hash_on_g2, map_to_g2, GeneratorG1};
use super::errors::DecodeError;
use super::g2::G2Point;
use super::keys::{PublicKey, SecretKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub point: G2Point,
}

impl Signature {
    /// Instantiate a new Signature from a message and a SecretKey.
    pub fn new(msg: &[u8], d: u64, sk: &SecretKey) -> Self {
        let hash_point = hash_on_g2(msg, d);
        let sig = hash_point.mul(&sk.x);
        Self {
            point: G2Point::from_raw(sig),
        }
    }

    /// Instantiate a new Signature from a message and a SecretKey, where the message has already
    /// been hashed.
    pub fn new_hashed(msg_hash_real: &[u8], msg_hash_imaginary: &[u8], sk: &SecretKey) -> Self {
        let hash_point = map_to_g2(msg_hash_real, msg_hash_imaginary);
        let sig = hash_point.mul(&sk.x);
        Self {
            point: G2Point::from_raw(sig),
        }
    }

    /// Verify the Signature against a PublicKey.
    ///
    /// In theory, should only return true if the PublicKey matches the SecretKey used to
    /// instantiate the Signature.
    pub fn verify(&self, msg: &[u8], d: u64, pk: &PublicKey) -> bool {
        // Check points are valid
        if self.point.is_infinity() || pk.point.is_infinity() {
            return false;
        }

        let msg_hash_point = hash_on_g2(msg, d);
        let mut lhs = ate_pairing(self.point.as_raw(), &GeneratorG1);
        let mut rhs = ate_pairing(&msg_hash_point, &pk.point.as_raw());
        lhs.equals(&mut rhs)
    }

    /// Verify the Signature against a PublicKey, where the message has already been hashed.
    ///
    /// The supplied hash will be mapped to G1.
    ///
    /// In theory, should only return true if the PublicKey matches the SecretKey used to
    /// instantiate the Signature.
    pub fn verify_hashed(
        &self,
        msg_hash_real: &[u8],
        msg_hash_imaginary: &[u8],
        pk: &PublicKey,
    ) -> bool {
        // Check points are valid
        if self.point.is_infinity() || pk.point.is_infinity() {
            return false;
        }

        let msg_hash_point = map_to_g2(msg_hash_real, msg_hash_imaginary);
        let mut lhs = ate_pairing(self.point.as_raw(), &GeneratorG1);
        let mut rhs = ate_pairing(&msg_hash_point, &pk.point.as_raw());
        lhs.equals(&mut rhs)
    }

    /// Instantiate a Signature from a serialized Signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, DecodeError> {
        let point = G2Point::from_bytes(bytes)?;
        Ok(Self { point })
    }

    /// Serialize the Signature.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.point.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::super::keys::Keypair;
    use super::*;

    #[test]
    fn basic_sign_verify() {
        let keypair = Keypair::random();
        let sk = keypair.sk;
        let vk = keypair.pk;

        let messages = vec!["", "a", "an example"];
        let domain = 42;

        for m in messages {
            /*
             * Simple sign and verify
             */
            let bytes = m.as_bytes();
            let mut sig = Signature::new(&bytes, domain, &sk);
            assert!(sig.verify(&bytes, domain, &vk));

            /*
             * Test serializing, then deserializing the signature
             */
            let sig_bytes = sig.as_bytes();
            let mut new_sig = Signature::from_bytes(&sig_bytes).unwrap();
            assert_eq!(&sig.as_bytes(), &new_sig.as_bytes());
            assert!(new_sig.verify(&bytes, domain, &vk));
        }
    }

    #[test]
    fn verification_failure() {
        let keypair = Keypair::random();
        let sk = keypair.sk;
        let vk = keypair.pk;
        let domain = 42;

        let mut msg = "Some msg";
        let sig = Signature::new(&msg.as_bytes(), domain, &sk);
        msg = "Other msg";
        assert_eq!(sig.verify(&msg.as_bytes(), domain, &vk), false);
        msg = "";
        assert_eq!(sig.verify(&msg.as_bytes(), domain, &vk), false);
    }
}
