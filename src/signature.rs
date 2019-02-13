extern crate amcl;

use super::amcl_utils::{ate_pairing, hash_on_g2, map_to_g2, GeneratorG1, GroupG2};
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
        let mut sig = hash_point.mul(&sk.x);
        sig.affine();
        Self {
            point: G2Point::from_raw(sig),
        }
    }

    /// Instantiate a new Signature from GroupG2 point.
    pub fn new_from_raw(pt: GroupG2) -> Self {
        Self {
            point: G2Point::from_raw(pt),
        }
    }

    /// Instantiate a new Signature from a message and a SecretKey, where the message has already
    /// been hashed.
    pub fn new_hashed(msg_hash_real: &[u8], msg_hash_imaginary: &[u8], sk: &SecretKey) -> Self {
        let hash_point = map_to_g2(msg_hash_real, msg_hash_imaginary);
        let mut sig = hash_point.mul(&sk.x);
        sig.affine();
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

        let mut msg_hash_point = hash_on_g2(msg, d);
        msg_hash_point.affine();
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

        let mut msg_hash_point = map_to_g2(msg_hash_real, msg_hash_imaginary);
        msg_hash_point.affine();
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
    extern crate hex;
    extern crate yaml_rust;

    use super::super::keys::Keypair;
    use super::*;
    use super::super::amcl_utils::{compress_g1, compress_g2, GroupG1, GroupG2};
    use self::yaml_rust::yaml;
    use std::{fs::File, io::prelude::*, path::PathBuf};

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
    fn verification_failure_message() {
        let keypair = Keypair::random();
        let sk = keypair.sk;
        let vk = keypair.pk;

        let mut msg = "Some msg";
        let domain = 42;
        let sig = Signature::new(&msg.as_bytes(), domain, &sk);
        msg = "Other msg";
        assert_eq!(sig.verify(&msg.as_bytes(), domain, &vk), false);
        msg = "";
        assert_eq!(sig.verify(&msg.as_bytes(), domain, &vk), false);
    }

    #[test]
    fn verification_failure_domain() {
        let keypair = Keypair::random();
        let sk = keypair.sk;
        let vk = keypair.pk;

        let msg = "Some msg";
        let mut domain = 42;
        let sig = Signature::new(&msg.as_bytes(), domain, &sk);
        domain = 11;
        assert_eq!(sig.verify(&msg.as_bytes(), domain, &vk), false);
    }

    #[test]
    fn case04_sign_messages() {
        // Run tests from test_bls.yml
        let mut file = {
            let mut file_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            file_path_buf.push("src/test_vectors/test_bls.yml");

            File::open(file_path_buf).unwrap()
        };
        let mut yaml_str = String::new();
        file.read_to_string(&mut yaml_str).unwrap();
        let docs = yaml::YamlLoader::load_from_str(&yaml_str).unwrap();
        let doc = &docs[0];

        // Select test case04
        let test_cases = doc["case04_sign_messages"].as_vec().unwrap();

        // Verify input against output for each pair
        for test_case in test_cases {
            // Convert input to rust formats
            let input = test_case["input"].clone();
            // Convert domain from yaml to u64
            let domain = input["domain"].as_str().unwrap();
            let domain = domain.trim_left_matches("0x");
            let domain = u64::from_str_radix(domain, 16).unwrap();

            // Convert msg from yaml to bytes (Vec<u8>)
            let msg = input["message"].as_str().unwrap();
            let msg = msg.trim_left_matches("0x");
            let msg = hex::decode(msg).unwrap();

            // Convert privateKey from yaml to SecretKey
            let privkey = input["privkey"].as_str().unwrap();
            let privkey = privkey.trim_left_matches("0x");
            let mut privkey = hex::decode(privkey).unwrap();
            while privkey.len() < 48 {
                // Prepend until correct length
                privkey.insert(0, 0);
            }
            let sk = SecretKey::from_bytes(&privkey).unwrap();

            // Create signature
            let sig = Signature::new(&msg, domain, &sk);
            let mut sig = sig.point.as_raw().clone();
            let compressed_sig = compress_g2(&mut sig);

            // Convert given output to rust compressed signature (Vec<u8>)
            let output = test_case["output"].as_str().unwrap();
            let output = output.trim_left_matches("0x");
            let output = hex::decode(output).unwrap();

            assert_eq!(output, compressed_sig);
        }
    }
}
