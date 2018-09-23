extern crate amcl;
extern crate rand;

use super::amcl_utils::{
    BigNum,
    GroupG2,
    CURVE_ORDER,
    GeneratorG2,
    MODBYTES,
    G2_BYTE_SIZE,
    MOD_BYTE_SIZE,
};
use super::rng::get_seeded_rng;
use super::errors::DecodeError;

#[derive(Clone)]
/// A BLS secret key.
pub struct SecretKey {
    pub x: BigNum
}

impl SecretKey {
    /// Generate a new SecretKey using `rand::thread_rng` to seed the `amcl::rand::RAND` PRNG.
    pub fn random() -> Self {
        let mut r = get_seeded_rng(256);
        let x = BigNum::randomnum(&BigNum::new_ints(&CURVE_ORDER), &mut r);
        SecretKey {
            x
        }
    }

    /// Instantiate a SecretKey from existing bytes.
    pub fn from_bytes(bytes: &[u8])
        -> Result<SecretKey, DecodeError>
    {
        if bytes.len() != MOD_BYTE_SIZE {
            return Err(DecodeError::IncorrectSize)
        }
        Ok(SecretKey {
            x: BigNum::frombytes(bytes)
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

/// A BLS public key.
pub struct PublicKey {
    pub point: GroupG2
}

impl PublicKey {
    /// Instantiate a PublicKey from some SecretKey.
    pub fn from_secret_key(sk: &SecretKey) -> Self {
        PublicKey {
            point: GeneratorG2.mul(&sk.x),
        }
    }

    /// Instantiate a PublicKey from some bytes.
    pub fn from_bytes(bytes: &[u8])
        -> Result<PublicKey, DecodeError>
    {
        if bytes.len() != G2_BYTE_SIZE {
            Err(DecodeError::IncorrectSize)
        } else {
            Ok(Self {
                point: GroupG2::frombytes(bytes)
            })
        }
    }

    /// Export the PublicKey to some bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut temp = GroupG2::new();
        temp.copy(&self.point);
        let mut bytes: [u8; G2_BYTE_SIZE] = [0; G2_BYTE_SIZE];
        temp.tobytes(&mut bytes);
        bytes.to_vec()
    }
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

/// A helper which stores a BLS public and private key pair.
#[derive(Clone)]
pub struct Keypair {
    pub sk: SecretKey,
    pub pk: PublicKey
}

impl Keypair {
    /// Instantiate a Keypair using SecretKey::random().
    pub fn random() -> Self {
        let sk = SecretKey::random();
        let pk = PublicKey::from_secret_key(&sk);
        Keypair {
            sk,
            pk
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::signature::Signature;

    #[test]
    fn test_secret_key_serialization_isomorphism() {
        let sk_bytes = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            78, 252, 122, 126, 32, 0, 75, 89, 252, 31, 42,
            130, 254, 88, 6, 90, 138, 202, 135, 194, 233,
            117, 181, 75, 96, 238, 79, 100, 237, 59, 140, 111
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let decoded_sk = sk.as_bytes();
        assert_eq!(decoded_sk, sk_bytes);
    }

    #[test]
    fn test_public_key_serialization_isomorphism() {
        let sk_bytes = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            78, 252, 122, 126, 32, 0, 75, 89, 252, 31, 42,
            130, 254, 88, 6, 90, 138, 202, 135, 194, 233,
            117, 181, 75, 96, 238, 79, 100, 237, 59, 140, 111
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            78, 252, 122, 126, 32, 0, 75, 89, 252, 31, 42,
            130, 254, 88, 6, 90, 138, 202, 135, 194, 233,
            117, 181, 75, 96, 238, 79, 100, 237, 59, 140, 111
        ];
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&sk);

        let message = "cats".as_bytes();
        let signature = Signature::new(&message, &sk);
        assert!(signature.verify(&message, &pk));

        let pk_bytes = pk.as_bytes();
        let pk = PublicKey::from_bytes(&pk_bytes).unwrap();
        assert!(signature.verify(&message, &pk));
    }

    #[test]
    fn test_random_secret_key_can_sign() {
        let sk = SecretKey::random();
        let pk = PublicKey::from_secret_key(&sk);

        let message = "cats".as_bytes();
        let signature = Signature::new(&message, &sk);
        assert!(signature.verify(&message, &pk));
    }
}
