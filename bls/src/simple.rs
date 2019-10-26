use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use super::common::{SigKey, VerKey};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use common::{Params, MESSAGE_DOMAIN_PREFIX};
use {ate_2_pairing, SignatureGroup, SignatureGroupVec};
use {ate_multi_pairing, VerkeyGroup};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub point: SignatureGroup,
}

impl Signature {
    // Signature = H_0(msg) * sk
    pub fn new(msg: &[u8], sig_key: &SigKey) -> Self {
        let hash_point = Self::hash_message(msg);
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
        let msg_hash_point = Self::hash_message(msg);
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

    /// Batch verification of signatures. Takes a vector of 3-tuple where each tuple has a message,
    /// signature and public key. Messages can be same or different
    pub fn batch_verify(msgs_sigs: Vec<(&[u8], &Signature, &VerKey)>, params: &Params) -> bool {
        let r = FieldElement::random();
        let r_vec = FieldElementVector::new_vandermonde_vector(&r, msgs_sigs.len());
        let mut sigs = SignatureGroupVec::with_capacity(msgs_sigs.len());
        let mut hs = vec![];
        let mut vs = vec![];
        for (i, (msg, sig, vk)) in msgs_sigs.iter().enumerate() {
            sigs.push(sig.point.clone());
            hs.push(Signature::hash_message(msg));
            // The multiplication with &r_vec[i] can be moved to message instead of verkey but
            // since verkey is in group G1 by default and operations in G1 are cheaper.
            // A better way would be to have code conditional on features such that
            // multiplication is moved to message when messages are in G1 and verkey in G2.
            vs.push(&vk.point * &r_vec[i]);
        }
        let aggr_sig = sigs.multi_scalar_mul_var_time(&r_vec).unwrap();
        let mut pairings = hs
            .iter()
            .zip(vs.iter())
            .map(|(h, v)| (h, v))
            .collect::<Vec<(&SignatureGroup, &VerkeyGroup)>>();
        let neg_g = params.g.negation();
        pairings.push((&aggr_sig, &neg_g));
        ate_multi_pairing(pairings).is_one()
    }

    /// Batch verification of signatures. Takes a vector of 3-tuple where each tuple has a message,
    /// signature and public key. Assumes all messages to be distinct
    pub fn batch_verify_distinct_msgs(
        msgs_sigs: Vec<(&[u8], &Signature, &VerKey)>,
        params: &Params,
    ) -> bool {
        let mut aggr_sig = SignatureGroup::new();
        let mut hs = vec![];
        let mut vs = vec![];
        for (msg, sig, vk) in msgs_sigs {
            aggr_sig += &sig.point;
            hs.push(Signature::hash_message(msg));
            vs.push(vk);
        }
        let mut pairings = hs
            .iter()
            .zip(vs)
            .map(|(h, v)| (h, &v.point))
            .collect::<Vec<(&SignatureGroup, &VerkeyGroup)>>();
        let neg_g = params.g.negation();
        pairings.push((&aggr_sig, &neg_g));
        ate_multi_pairing(pairings).is_one()
    }

    pub fn from_bytes(sig_bytes: &[u8]) -> Result<Signature, SerzDeserzError> {
        SignatureGroup::from_bytes(sig_bytes).map(|point| Signature { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }

    /// Hash message to group element. H_0 from the paper.
    pub(crate) fn hash_message(msg: &[u8]) -> SignatureGroup {
        SignatureGroup::from_msg_hash(&[&MESSAGE_DOMAIN_PREFIX, msg].concat())
    }
}

#[cfg(test)]
mod tests {
    // TODO: Add tests for failure
    // TODO: Add more test vectors
    use super::*;
    use crate::common::Keypair;
    use rand;
    use rand::Rng;
    use std::time::Instant;

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
            let sig1 = Signature::from_bytes(&bs).unwrap();
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

    #[test]
    fn batch_verify() {
        let params = Params::new("test".as_bytes());
        let mut keypairs = vec![];
        let mut msgs = vec![];
        let mut sigs = vec![];
        let mut rng = rand::thread_rng();
        let count = 5;
        for _ in 0..count {
            let keypair = Keypair::new(None, &params);
            let msg = (0..10).map(|_| rng.gen_range(1, 100)).collect::<Vec<u8>>();
            let sig = Signature::new(&msg, &keypair.sig_key);
            sigs.push(sig);
            msgs.push(msg);
            keypairs.push(keypair);
        }

        let start = Instant::now();
        for i in 0..count {
            assert!(sigs[i].verify(&msgs[i], &keypairs[i].ver_key, &params));
        }
        println!(
            "Naive verify for {} sigs takes {:?}",
            count,
            start.elapsed()
        );

        let start = Instant::now();
        let msgs_sigs = (0..count)
            .map(|i| (msgs[i].as_slice(), &sigs[i], &keypairs[i].ver_key))
            .collect::<Vec<_>>();
        assert!(Signature::batch_verify(msgs_sigs, &params));
        println!(
            "Batch verify for {} sigs takes {:?}",
            count,
            start.elapsed()
        );

        let start = Instant::now();
        let msgs_sigs = (0..count)
            .map(|i| (msgs[i].as_slice(), &sigs[i], &keypairs[i].ver_key))
            .collect::<Vec<_>>();
        assert!(Signature::batch_verify_distinct_msgs(msgs_sigs, &params));
        println!(
            "Batch verify assuming distinct messages for {} sigs takes {:?}",
            count,
            start.elapsed()
        );
    }
}
