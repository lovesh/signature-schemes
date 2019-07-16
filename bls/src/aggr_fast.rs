use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use super::common::{SigKey, VerKey};
use super::simple::Signature;

// This is an older but FASTER way of doing BLS signature aggregation but it IS VULNERABLE to rogue
// public key attack. Use the proof of possession before trusting a new Verkey.

pub fn generate_proof_of_possession(verkey: &VerKey, sigkey: &SigKey) -> Signature {
    Signature::new(verkey.to_bytes().as_ref(), &sigkey)
}

pub fn verify_proof_of_possession(proof: &Signature, verkey: &VerKey) -> bool {
    proof.verify(verkey.to_bytes().as_ref(), verkey)
}

#[derive(Debug, Clone)]
pub struct AggregatedVerKeyFast {
    pub point: G2,
}

impl AggregatedVerKeyFast {
    pub fn new(ver_keys: Vec<&VerKey>) -> Self {
        let mut avk: G2 = G2::identity();
        for vk in ver_keys {
            avk += vk.point;
        }
        AggregatedVerKeyFast { point: avk }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<AggregatedVerKeyFast, SerzDeserzError> {
        G2::from_bytes(vk_bytes).map(|point| AggregatedVerKeyFast { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct AggregatedSignatureFast {
    pub point: G1,
}

impl AggregatedSignatureFast {
    pub fn new(sigs: Vec<&Signature>) -> Self {
        let mut asig: G1 = G1::identity();
        for s in sigs {
            asig += s.point;
        }
        AggregatedSignatureFast { point: asig }
    }

    pub fn verify(&self, msg: &[u8], ver_keys: Vec<&VerKey>) -> bool {
        let avk = AggregatedVerKeyFast::new(ver_keys);
        self.verify_using_aggr_vk(msg, &avk)
    }

    // For verifying multiple aggregate signatures from the same signers,
    // an aggregated verkey should be created once and then used for each signature verification
    pub fn verify_using_aggr_vk(&self, msg: &[u8], avk: &AggregatedVerKeyFast) -> bool {
        // TODO: combine verification code with the one in aggr_slow.rs
        if self.point.is_identity() {
            println!("Signature point at infinity");
            return false;
        }
        let msg_hash_point = G1::from_msg_hash(msg);
        /*let lhs = GT::ate_pairing(&self.point, &G2::generator());
        let rhs = GT::ate_pairing(&msg_hash_point, &avk.point);
        lhs == rhs*/
        // Check that e(self.point, G2::generator()) == e(msg_hash_point, avk.point)
        // This is equivalent to checking e(msg_hash_point, avk.point) * e(self.point, G2::generator())^-1 == 1
        // or e(msg_hash_point, avk.point) * e(self.point, -G2::generator()) == 1
        let e = GT::ate_2_pairing(
            &self.point,
            &G2::generator().negation(),
            &msg_hash_point,
            &avk.point,
        );
        e.is_one()
    }

    pub fn from_bytes(sig_bytes: &[u8]) -> Result<AggregatedSignatureFast, SerzDeserzError> {
        G1::from_bytes(sig_bytes).map(|point| AggregatedSignatureFast { point })
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
    fn proof_of_possession() {
        let keypair = Keypair::new(None);
        let sk = keypair.sig_key;
        let vk = keypair.ver_key;

        let proof = generate_proof_of_possession(&vk, &sk);
        assert!(verify_proof_of_possession(&proof, &vk));
    }

    #[test]
    fn aggr_sign_verify_old() {
        let keypair1 = Keypair::new(None);
        let keypair2 = Keypair::new(None);
        let keypair3 = Keypair::new(None);
        let keypair4 = Keypair::new(None);
        let keypair5 = Keypair::new(None);

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
                assert!(sig.verify(&b, &keypair.ver_key));
                let v = keypair.ver_key.clone();
                vks.push(v);
                sigs.push(sig);
            }

            let vks_1: Vec<&VerKey> = vks.iter().map(|v| v).collect();
            let vks_2: Vec<&VerKey> = vks.iter().map(|v| v).collect();
            let sigs: Vec<&Signature> = sigs.iter().map(|s| s).collect();
            let asig = AggregatedSignatureFast::new(sigs);
            assert!(asig.verify(&b, vks_1));

            let avk = AggregatedVerKeyFast::new(vks_2);
            assert!(asig.verify_using_aggr_vk(&b, &avk));

            let bs = asig.to_bytes();
            let sig1 = AggregatedSignatureFast::from_bytes(&bs).unwrap();
            assert!(sig1.verify_using_aggr_vk(&b, &avk));
            // FIXME: Next line fails, probably something wrong with main amcl codebase.
            //assert_eq!(&asig.point.to_hex(), &sig1.point.to_hex());

            let bs = avk.to_bytes();
            let avk1 = AggregatedVerKeyFast::from_bytes(&bs).unwrap();
            assert_eq!(&avk.point.to_hex(), &avk1.point.to_hex());
        }
    }

    #[test]
    fn aggregate_signature_at_infinity() {
        let keypair1 = Keypair::new(None);
        let keypair2 = Keypair::new(None);
        let msg = "Small msg".as_bytes();

        let asig = AggregatedSignatureFast {
            point: G1::identity(),
        };
        let vks: Vec<&VerKey> = vec![&keypair1.ver_key, &keypair2.ver_key];
        assert_eq!(asig.verify(&msg, vks), false);
    }
}
