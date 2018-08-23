extern crate amcl;

use super::amcl_utils::{hash_on_GroupG1, ate_pairing};
use super::types::{GroupG1, GroupG2};
use super::constants::{CURVE_ORDER, GeneratorG2, GroupG2_SIZE};
use super::common::{SigKey, VerKey, Keypair};
use super::simple::Signature;
use bls::amcl_utils::get_G2_point_from_bytes;
use bls::amcl_utils::get_bytes_for_G2_point;
use bls::errors::SerzDeserzError;
use bls::amcl_utils::get_G1_point_from_bytes;
use bls::amcl_utils::get_bytes_for_G1_point;


// This is an older but faster way of doing BLS signature aggregation but it is vulnerable to rogue
// public key attack . Use the proof of possession before trusting a new Verkey.


pub fn generate_proof_of_possession(verkey: &VerKey, sigkey: &SigKey) -> Signature {
    Signature::new(verkey.to_bytes().as_ref(), &sigkey)
}

pub fn verify_proof_of_possession(proof: &Signature, verkey: &VerKey) -> bool {
    proof.verify(verkey.to_bytes().as_ref(), verkey)
}

pub struct AggregatedVerKeyOld {
    pub point: GroupG2
}

impl AggregatedVerKeyOld {
    pub fn new(ver_keys: Vec<&VerKey>) -> Self {
        let mut avk: GroupG2 = GroupG2::new();
        avk.inf();
        println!("Aggr vk={}", &avk.tostring());
        for vk in ver_keys {
            avk.add(&vk.point);
            println!("Aggr vk={}", &avk.tostring());
        }
        AggregatedVerKeyOld { point: avk }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<AggregatedVerKeyOld, SerzDeserzError> {
        Ok(AggregatedVerKeyOld {
            point: get_G2_point_from_bytes(vk_bytes)?
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        get_bytes_for_G2_point(&self.point)
    }
}

pub struct AggregatedSignatureOld {
    pub point: GroupG1
}

impl AggregatedSignatureOld {
    pub fn new(sigs: Vec<&Signature>) -> Self {
        let mut asig: GroupG1 = GroupG1::new();
        asig.inf();
        println!("Aggr sig={}", &asig.tostring());
        for s in sigs {
            asig.add(&s.point);
            println!("Aggr sig={}", &asig.tostring());
        }
        AggregatedSignatureOld {
            point: asig
        }
    }

    pub fn verify(&self, msg: &[u8], ver_keys: Vec<&VerKey>) -> bool {
        let avk = AggregatedVerKeyOld::new(ver_keys);
        self.verify_using_aggr_vk(msg, &avk)
    }

    // For verifying multiple aggregate signatures from the same signers,
    // an aggregated verkey should be created once and then used for each signature verification
    pub fn verify_using_aggr_vk(&self, msg: &[u8], avk: &AggregatedVerKeyOld) -> bool {
        if self.point.is_infinity() {
            println!("Signature point at infinity");
            return false;
        }
        let msg_hash_point = hash_on_GroupG1(msg);
        let mut lhs = ate_pairing(&GeneratorG2, &self.point);
        let mut rhs = ate_pairing(&avk.point, &msg_hash_point);
        lhs.equals(&mut rhs)
    }

    pub fn from_bytes(sig_bytes: &[u8]) -> Result<AggregatedSignatureOld, SerzDeserzError> {
        Ok(AggregatedSignatureOld {
            point: get_G1_point_from_bytes(sig_bytes)?
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        get_bytes_for_G1_point(&self.point)
    }
}

#[cfg(test)]
mod tests {
    // TODO: Add tests for failure
    // TODO: Add more test vectors
    use super::*;

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
            let mut asig = AggregatedSignatureOld::new(sigs);
            assert!(asig.verify(&b, vks_1));

            let mut avk = AggregatedVerKeyOld::new(vks_2);
            assert!(asig.verify_using_aggr_vk(&b, &avk));

            let bs = asig.to_bytes();
            let mut sig1 = AggregatedSignatureOld::from_bytes(&bs).unwrap();
            assert_eq!(&asig.point.tostring(), &sig1.point.tostring());

            let bs = avk.to_bytes();
            let mut avk1 = AggregatedVerKeyOld::from_bytes(&bs).unwrap();
            assert_eq!(&avk.point.tostring(), &avk1.point.tostring());
        }
    }

    #[test]
    fn aggregate_signature_at_infinity() {
        let keypair1 = Keypair::new(None);
        let keypair2 = Keypair::new(None);
        let msg = "Small msg".as_bytes();

        let mut asig = AggregatedSignatureOld { point: GroupG1::new() };
        asig.point.inf();
        let vks: Vec<&VerKey> = vec![&keypair1.ver_key, &keypair2.ver_key];
        assert_eq!(asig.verify(&msg, vks), false);
    }
}