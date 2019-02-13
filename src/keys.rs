extern crate amcl;
extern crate rand;

use super::amcl_utils::{BigNum, GeneratorG1, CURVE_ORDER, MODBYTES, MOD_BYTE_SIZE};
use super::errors::DecodeError;
use super::g1::G1Point;
use super::rng::get_seeded_rng;
use std::fmt;

#[derive(Clone)]
/// A BLS secret key.
pub struct SecretKey {
    pub x: BigNum,
}

impl SecretKey {
    /// Generate a new SecretKey using `rand::thread_rng` to seed the `amcl::rand::RAND` PRNG.
    pub fn random() -> Self {
        let mut r = get_seeded_rng(256);
        let x = BigNum::randomnum(&BigNum::new_ints(&CURVE_ORDER), &mut r);
        SecretKey { x }
    }

    /// Instantiate a SecretKey from existing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, DecodeError> {
        if bytes.len() != MOD_BYTE_SIZE {
            return Err(DecodeError::IncorrectSize);
        }
        Ok(SecretKey {
            x: BigNum::frombytes(bytes),
        })
    }

    /// Export the SecretKey to bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut temp = BigNum::new_copy(&self.x);
        let mut bytes: [u8; MODBYTES] = [0; MODBYTES];
        temp.tobytes(&mut bytes);
        bytes.to_vec()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut temp = BigNum::new();
        temp.copy(&self.x);
        write!(f, "{}", temp.tostring())
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &SecretKey) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for SecretKey {}

/// A BLS public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub point: G1Point,
}

impl PublicKey {
    /// Instantiate a PublicKey from some SecretKey.
    pub fn from_secret_key(sk: &SecretKey) -> Self {
        PublicKey {
            point: G1Point::from_raw(GeneratorG1.mul(&sk.x)),
        }
    }

    /// Instantiate a PublicKey from some bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, DecodeError> {
        let point = G1Point::from_bytes(bytes)?;
        Ok(Self { point })
    }

    /// Export the PublicKey to some bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.point.as_bytes()
    }
}

/// A helper which stores a BLS public and private key pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keypair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

impl Keypair {
    /// Instantiate a Keypair using SecretKey::random().
    pub fn random() -> Self {
        let sk = SecretKey::random();
        let pk = PublicKey::from_secret_key(&sk);
        Keypair { sk, pk }
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::super::signature::Signature;
    use super::*;

    #[test]
    fn test_secret_key_serialization_isomorphism() {
        let sk_bytes = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let decoded_sk = sk.as_bytes();
        assert_eq!(decoded_sk, sk_bytes);
    }

    #[test]
    fn test_public_key_serialization_isomorphism() {
        let sk_bytes = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&sk);
        let decoded_pk = pk.as_bytes();
        let encoded_pk = PublicKey::from_bytes(&decoded_pk).unwrap();
        let re_recoded_pk = encoded_pk.as_bytes();
        assert_eq!(decoded_pk, re_recoded_pk);
    }

    #[test]
    fn test_signature_verify_with_serialized_public_key() {
        let sk_bytes = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&sk);
        let domain = 42;

        let message = "cats".as_bytes();
        let signature = Signature::new(&message, domain, &sk);
        assert!(signature.verify(&message, domain, &pk));

        let pk_bytes = pk.as_bytes();
        let pk = PublicKey::from_bytes(&pk_bytes).unwrap();
        assert!(signature.verify(&message, domain, &pk));
    }

    #[test]
    fn test_random_secret_key_can_sign() {
        let sk = SecretKey::random();
        let pk = PublicKey::from_secret_key(&sk);
        let domain = 42;

        let message = "cats".as_bytes();
        let signature = Signature::new(&message, domain, &sk);
        assert!(signature.verify(&message, domain, &pk));
    }

    // Test vector from https://github.com/ethereum/eth2.0-tests/blob/master/bls/test_bls.yml
    // case03_private_to_public_key
    #[test]
    fn case03_private_to_public_key() {
        let secret: Vec<u8> = hex::decode("00000000000000000000000000000000263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3").unwrap();
        let sk = SecretKey::from_bytes(&secret).unwrap();
        let pk = PublicKey::from_secret_key(&sk).as_bytes();
        let pk_from_test: Vec<u8> = hex::decode("0491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a").unwrap();
        assert_eq!(&pk[1..49], pk_from_test.as_slice());

        let secret: Vec<u8> = hex::decode("0000000000000000000000000000000047b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138").unwrap();
        let sk = SecretKey::from_bytes(&secret).unwrap();
        let pk = PublicKey::from_secret_key(&sk).as_bytes();
        let pk_from_test: Vec<u8> = hex::decode("1301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81").unwrap();
        assert_eq!(&pk[1..49], pk_from_test.as_slice());

        let secret: Vec<u8> = hex::decode("00000000000000000000000000000000328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216").unwrap();
        let sk = SecretKey::from_bytes(&secret).unwrap();
        let pk = PublicKey::from_secret_key(&sk).as_bytes();
        let pk_from_test: Vec<u8> = hex::decode("153d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f").unwrap();
        assert_eq!(&pk[1..49], pk_from_test.as_slice());
    }
}
