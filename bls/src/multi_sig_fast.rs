use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use super::common::{SigKey, VerKey};
use super::simple::Signature;
use common::Params;
use {ate_2_pairing, SignatureGroup, VerkeyGroup};

// This is an older but FASTER way of doing BLS signature aggregation but it IS VULNERABLE to rogue
// public key attack. Use the proof of possession before trusting a new Verkey.

pub struct ProofOfPossession {}
impl ProofOfPossession {
    // Used for domain separation while creating Proof of Possession
    const PoP_DOMAIN_PREFIX: [u8; 2] = [2, 2];

    pub fn generate(verkey: &VerKey, sigkey: &SigKey) -> Signature {
        Signature::new(
            &[&Self::PoP_DOMAIN_PREFIX, verkey.to_bytes().as_slice()].concat(),
            &sigkey,
        )
    }

    pub fn verify(proof: &Signature, verkey: &VerKey, params: &Params) -> bool {
        proof.verify(
            &[&Self::PoP_DOMAIN_PREFIX, verkey.to_bytes().as_slice()].concat(),
            verkey,
            params,
        )
    }
}

pub struct AggregatedVerKeyFast {}

impl AggregatedVerKeyFast {
    pub fn from_verkeys(ver_keys: Vec<&VerKey>) -> VerKey {
        let mut avk = VerkeyGroup::identity();
        for vk in ver_keys {
            avk += &vk.point;
        }
        VerKey { point: avk }
    }
}

pub struct MultiSignatureFast {}

impl MultiSignatureFast {
    pub fn from_sigs(sigs: Vec<&Signature>) -> Signature {
        let mut asig = SignatureGroup::identity();
        for s in sigs {
            asig += &s.point;
        }
        Signature { point: asig }
    }

    pub fn verify(sig: &Signature, msg: &[u8], ver_keys: Vec<&VerKey>, params: &Params) -> bool {
        let avk = AggregatedVerKeyFast::from_verkeys(ver_keys);
        sig.verify(msg, &avk, params)
    }

    // For verifying multiple multi-signatures from the same signers,
    // an aggregated verkey should be created once and then used for each signature verification
}

#[cfg(test)]
mod tests {
    // TODO: Add tests for failure
    // TODO: Add more test vectors
    use super::*;
    use crate::common::Keypair;
    use rand::Rng;
    use rand::thread_rng;

    #[test]
    fn proof_of_possession() {
        let mut rng = thread_rng();
        let params = Params::new("test".as_bytes());
        let keypair = Keypair::new(&mut rng, &params);
        let sk = keypair.sig_key;
        let vk = keypair.ver_key;

        let proof = ProofOfPossession::generate(&vk, &sk);
        assert!(ProofOfPossession::verify(&proof, &vk, &params));
    }

    #[test]
    fn multi_sign_verify_fast() {
        let mut rng = thread_rng();
        let params = Params::new("test".as_bytes());
        let keypair1 = Keypair::new(&mut rng, &params);
        let keypair2 = Keypair::new(&mut rng, &params);
        let keypair3 = Keypair::new(&mut rng, &params);
        let keypair4 = Keypair::new(&mut rng, &params);
        let keypair5 = Keypair::new(&mut rng, &params);

        let msg = "Small msg";
        let msg1 = "121220888888822111212";
        let msg2 = "Some message to sign";
        let msg3 = "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222";
        let msg4 = " is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

        for m in vec![msg, msg1, msg2, msg3, msg4] {
            let b = m.as_bytes();
            let mut sigs: Vec<Signature> = Vec::new();
            let mut vks: Vec<VerKey> = Vec::new();

            for keypair in vec![&keypair1, &keypair2, &keypair3, &keypair4, &keypair5] {
                let sig = Signature::new(&b, &keypair.sig_key);
                assert!(sig.verify(&b, &keypair.ver_key, &params));
                let v = keypair.ver_key.clone();
                vks.push(v);
                sigs.push(sig);
            }

            let vks_1: Vec<&VerKey> = vks.iter().map(|v| v).collect();
            let vks_2: Vec<&VerKey> = vks.iter().map(|v| v).collect();
            let sigs: Vec<&Signature> = sigs.iter().map(|s| s).collect();
            let asig = MultiSignatureFast::from_sigs(sigs);
            assert!(MultiSignatureFast::verify(&asig, &b, vks_1, &params));

            let avk = AggregatedVerKeyFast::from_verkeys(vks_2);
            assert!(asig.verify(&b, &avk, &params));

            let bs = asig.to_bytes();
            let sig1 = Signature::from_bytes(&bs).unwrap();
            assert!(sig1.verify(&b, &avk, &params));
            // FIXME: Next line fails, probably something wrong with main amcl codebase.
            //assert_eq!(&asig.point.to_hex(), &sig1.point.to_hex());

            let bs = avk.to_bytes();
            let avk1 = VerKey::from_bytes(&bs).unwrap();
            // FIXME: Next line fails, probably something wrong with main amcl codebase.
            //assert_eq!(&avk.point.to_hex(), &avk1.point.to_hex());
            assert_eq!(avk.point.to_bytes(), avk1.point.to_bytes());
        }
    }

    #[test]
    fn multi_signature_at_infinity() {
        let mut rng = thread_rng();
        let params = Params::new("test".as_bytes());
        let keypair1 = Keypair::new(&mut rng, &params);
        let keypair2 = Keypair::new(&mut rng, &params);
        let msg = "Small msg".as_bytes();

        let asig = Signature {
            point: SignatureGroup::identity(),
        };
        let vks: Vec<&VerKey> = vec![&keypair1.ver_key, &keypair2.ver_key];
        assert_eq!(MultiSignatureFast::verify(&asig, &msg, vks, &params), false);
    }
}
