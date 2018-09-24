extern crate amcl;

use super::amcl_utils::{
    GeneratorG2,
    hash_on_g1,
    ate_pairing
};
use super::g1::G1Point;
use super::g2::G2Point;
use super::keys::PublicKey;
use super::signature::Signature;
use super::errors::DecodeError;

/// Allows for the adding/combining of multiple BLS PublicKeys.
///
/// This may be used to verify some AggregateSignature.
#[derive(Debug, Clone, PartialEq)]
pub struct AggregatePublicKey {
    pub point: G2Point
}

impl AggregatePublicKey {
    /// Instantiate a new aggregate public key.
    ///
    /// The underlying point will be set to infinity.
    pub fn new()
        -> Self
    {
        let mut point = G2Point::new();
        // TODO: check why this inf call
        point.inf();
        Self {
            point
        }
    }

    /// Instantiate a new aggregate public key from a vector of PublicKeys.
    ///
    /// This is a helper method combining the `new()` and `add()` functions.
    pub fn from_public_keys(keys: &Vec<PublicKey>)
        -> Self
    {
        let mut agg_key = AggregatePublicKey::new();
        for key in keys {
            agg_key.add(&key)
        }
        agg_key
    }

    /// Add a PublicKey to the AggregatePublicKey.
    pub fn add(&mut self, public_key: &PublicKey) {
        self.point.add(&public_key.point);
        self.point.affine();
    }

    /// Instantiate an AggregatePublicKey from some serialized bytes.
    ///
    /// TODO: detail the exact format of these bytes (e.g., compressed, etc).
    pub fn from_bytes(bytes: &[u8])
        -> Result<AggregatePublicKey, DecodeError>
    {
        let point = G2Point::from_bytes(bytes)?;
        Ok(Self{ point })
    }

    /// Export the AggregatePublicKey to bytes.
    ///
    /// TODO: detail the exact format of these bytes (e.g., compressed, etc).
    pub fn as_bytes(&self) -> Vec<u8> {
        self.point.as_bytes()
    }
}

impl Default for AggregatePublicKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Allows for the adding/combining of multiple BLS Signatures.
///
/// This may be verified against some AggregatePublicKey.
#[derive(Debug, Clone, PartialEq)]
pub struct AggregateSignature {
    pub point: G1Point
}

impl AggregateSignature {
    /// Instantiates a new AggregateSignature.
    ///
    /// The underlying point will be set to infinity.
    pub fn new() -> Self {
        let mut point = G1Point::new();
        // TODO: check why this inf call
        point.inf();
        Self {
            point
        }
    }

    /// Add a Signature to the AggregateSignature.
    pub fn add(&mut self, signature: &Signature) {
        self.point.add(&signature.point);
        self.point.affine();
    }

    /// Verify this AggregateSignature against an AggregatePublicKey.
    ///
    /// All PublicKeys which signed across this AggregateSignature must be included in the
    /// AggregatePublicKey, otherwise verification will fail.
    pub fn verify(&self, msg: &[u8], avk: &AggregatePublicKey)
        -> bool
    {
        if self.point.is_infinity() {
            return false;
        }
        let msg_hash_point = hash_on_g1(msg);
        let mut lhs = ate_pairing(&GeneratorG2, self.point.as_raw());
        let mut rhs = ate_pairing(&avk.point.as_raw(), &msg_hash_point);
        lhs.equals(&mut rhs)
    }

    /// Instatiate an AggregateSignature from some bytes.
    ///
    /// TODO: detail the exact format of these bytes (e.g., compressed, etc).
    pub fn from_bytes(bytes: &[u8])
        -> Result<AggregateSignature, DecodeError>
    {
        let point = G1Point::from_bytes(bytes)?;
        Ok(Self{ point })
    }

    /// Export (serialize) the AggregateSignature to bytes.
    ///
    /// TODO: detail the exact format of these bytes (e.g., compressed, etc).
    pub fn as_bytes(&self) -> Vec<u8> {
        self.point.as_bytes()
    }
}


impl Default for AggregateSignature {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::keys::{
        SecretKey,
        Keypair,
    };

    #[test]
    fn test_aggregate_serialization() {
        let signing_secret_key_bytes = vec![
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 98,
            161, 50, 32, 254, 87, 16, 25, 167, 79, 192, 116, 176, 74,
            164, 217, 40, 57, 179, 15, 19, 21, 240, 100, 70, 127, 111,
            170, 129, 137, 42, 53],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53,
            72, 211, 104, 184, 68, 142, 208, 115, 22, 156, 97, 28,
            216, 228, 102, 4, 218, 116, 226, 166, 131, 67, 7, 40, 55,
            157, 167, 157, 127, 143, 13],
        ];
        let signing_keypairs: Vec<Keypair> = signing_secret_key_bytes
            .iter()
            .map(|bytes| {
                let sk = SecretKey::from_bytes(&bytes).unwrap();
                let pk = PublicKey::from_secret_key(&sk);
                Keypair{ sk, pk }
            }).collect();

        let message = "cats".as_bytes();

        let mut agg_sig = AggregateSignature::new();
        let mut agg_pub_key = AggregatePublicKey::new();
        for keypair in &signing_keypairs {
            let sig = Signature::new(&message, &keypair.sk);
            agg_sig.add(&sig);
            agg_pub_key.add(&keypair.pk);
        }
        let agg_sig_bytes = agg_sig.as_bytes();
        let agg_pub_bytes = agg_pub_key.as_bytes();

        let agg_sig = AggregateSignature::
            from_bytes(&agg_sig_bytes).unwrap();
        let agg_pub_key = AggregatePublicKey::
            from_bytes(&agg_pub_bytes).unwrap();


        assert!(agg_sig.verify(&message, &agg_pub_key));
    }

    fn map_secret_bytes_to_keypairs(secret_key_bytes: Vec<Vec<u8>>)
        -> Vec<Keypair>
    {
        let mut keypairs = vec![];
        for bytes in secret_key_bytes {
            let sk = SecretKey::from_bytes(&bytes).unwrap();
            let pk = PublicKey::from_secret_key(&sk);
            keypairs.push(Keypair{sk, pk})
        }
        keypairs
    }

    /// A helper for doing a comprehensive aggregate sig test.
    fn helper_test_aggregate_public_keys(control_kp: Keypair,
                                         signing_kps: Vec<Keypair>,
                                         non_signing_kps: Vec<Keypair>)
    {
        let signing_kps_subset = {
            let mut subset = vec![];
            for i in 0..signing_kps.len() - 1 {
                subset.push(signing_kps[i].clone());
            }
            subset
        };

        let messages = vec![
            "Small msg".as_bytes(),
            "cats lol".as_bytes(),
            &[42_u8; 133700]
        ];

        for message in messages {
            let mut agg_signature = AggregateSignature::new();
            let mut signing_agg_pub = AggregatePublicKey::new();
            for keypair in &signing_kps {
                let sig = Signature::new(&message, &keypair.sk);
                assert!(sig.verify(&message, &keypair.pk));
                assert!(!sig.verify(&message, &control_kp.pk));
                agg_signature.add(&sig);
                signing_agg_pub.add(&keypair.pk);
            }

            /*
             * The full set of signed keys should pass verification.
             */
            assert!(agg_signature.verify(&message, &signing_agg_pub));

            /*
             * A subset of signed keys should fail verification.
             */
            let mut subset_pub_keys = signing_kps_subset.iter().map(|kp| kp.pk.clone()).collect();
            let subset_agg_key = AggregatePublicKey::
                from_public_keys(&subset_pub_keys);
            assert!(!agg_signature.verify(&message, &subset_agg_key));
            // Sanity check the subset test by completing the set and verifying it.
            subset_pub_keys.push(signing_kps[signing_kps.len() - 1].pk.clone());
            let subset_agg_key = AggregatePublicKey::
                from_public_keys(&subset_pub_keys);
            assert!(agg_signature.verify(&message, &subset_agg_key));

            // TODO: test superset of pub keys.

            /*
             * A set of keys which did not sign the message at all should fail
             */
            let mut non_signing_pub_keys = non_signing_kps.iter()
                .map(|kp| kp.pk.clone()).collect();
            let non_signing_agg_key = AggregatePublicKey::
                from_public_keys(&non_signing_pub_keys);
            assert!(!agg_signature.verify(&message, &non_signing_agg_key));
        }
    }

    #[test]
    fn test_random_aggregate_public_keys() {
        let control_kp = Keypair::random();
        let signing_kps = vec![
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
        ];
        let non_signing_kps = vec![
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
        ];
        helper_test_aggregate_public_keys(control_kp,
                                          signing_kps,
                                          non_signing_kps);
    }

    #[test]
    fn test_known_aggregate_public_keys() {
        let control_secret_key_bytes = vec![
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            40, 129, 16, 229, 203, 159, 171, 37, 94, 38, 3, 24,
            17, 213, 243, 246, 122, 105, 202, 156, 186, 237, 54,
            148, 116, 130, 20, 138, 15, 134, 45, 73]
        ];
        let control_kps = map_secret_bytes_to_keypairs(
            control_secret_key_bytes);
        let control_kp = control_kps[0].clone();
        let signing_secret_key_bytes = vec![
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 98,
            161, 50, 32, 254, 87, 16, 25, 167, 79, 192, 116, 176, 74,
            164, 217, 40, 57, 179, 15, 19, 21, 240, 100, 70, 127, 111,
            170, 129, 137, 42, 53],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53,
            72, 211, 104, 184, 68, 142, 208, 115, 22, 156, 97, 28,
            216, 228, 102, 4, 218, 116, 226, 166, 131, 67, 7, 40, 55,
            157, 167, 157, 127, 143, 13],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 94,
            157, 163, 128, 239, 119, 116, 194, 162, 172, 189, 100,
            36, 33, 13, 31, 137, 177, 80, 73, 119, 126, 246, 215, 123,
            178, 195, 12, 141, 65, 65, 89],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 74,
            195, 255, 195, 62, 36, 197, 48, 100, 25, 121, 8, 191, 219,
            73, 136, 227, 203, 98, 123, 204, 27, 197, 66, 193, 107,
            115, 53, 5, 98, 137, 77],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 82,
            16, 65, 222, 228, 32, 47, 1, 245, 135, 169, 125, 46, 120,
            57, 149, 121, 254, 168, 52, 30, 221, 150, 186, 157, 141,
            25, 143, 175, 196, 21, 176],
        ];
        let signing_kps = map_secret_bytes_to_keypairs(
            signing_secret_key_bytes);
        let non_signing_secret_key_bytes = vec![
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6,
            235, 126, 159, 58, 82, 170, 175, 73, 188, 251, 60, 79,
            24, 164, 146, 88, 210, 177, 65, 62, 183, 124, 129, 109,
            248, 181, 29, 16, 128, 207, 23],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            100, 177, 235, 229, 217, 215, 204, 237, 178, 196, 182,
            51, 28, 147, 58, 24, 79, 134, 41, 185, 153, 133, 229,
            195, 32, 221, 247, 171, 91, 196, 65, 250],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            65, 154, 236, 86, 178, 14, 179, 117, 113, 4, 40, 173,
            150, 221, 23, 7, 117, 162, 173, 104, 172, 241, 111, 31,
            170, 241, 185, 31, 69, 164, 115, 126],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            13, 67, 192, 157, 69, 188, 53, 161, 77, 187, 133, 49,
            254, 165, 47, 189, 185, 150, 23, 231, 143, 31, 64, 208,
            134, 147, 53, 53, 228, 225, 104, 62],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            22, 66, 26, 11, 101, 38, 37, 1, 148, 156, 162, 211,
            37, 231, 37, 222, 172, 36, 224, 218, 187, 127, 122,
            195, 229, 234, 124, 91, 246, 73, 12, 120],
        ];
        let non_signing_kps = map_secret_bytes_to_keypairs(
            non_signing_secret_key_bytes);
        helper_test_aggregate_public_keys(control_kp,
                                          signing_kps,
                                          non_signing_kps);
    }
}
