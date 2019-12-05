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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    /// signature and public key. Messages can be the same or different.
    pub fn batch_verify<'a, T, K>(msgs_sigs: T, params: &Params) -> bool
        where T: IntoIterator<Item = &'a K> + ExactSizeIterator,
              K: AsRef<[u8]> + AsRef<Signature> + AsRef<VerKey> + 'a {
        let r = FieldElement::random();
        let r_vec = FieldElementVector::new_vandermonde_vector(&r, msgs_sigs.len());
        let mut sigs = SignatureGroupVec::with_capacity(msgs_sigs.len());
        let mut hs: Vec<SignatureGroup> = vec![];
        let mut vs = vec![];
        for (i, x) in msgs_sigs.into_iter().enumerate() {
            sigs.push(AsRef::<Signature>::as_ref(x).point.clone());
            hs.push(Signature::hash_message(x.as_ref()));
            // The multiplication with &r_vec[i] can be moved to message instead of verkey but
            // since verkey is in group G1 by default and operations in G1 are cheaper.
            // A better way would be to have code conditional on features such that
            // multiplication is moved to message when messages are in G1 and verkey in G2.
            vs.push(&AsRef::<VerKey>::as_ref(x).point * &r_vec[i]);
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
    pub fn batch_verify_distinct_msgs<'a, T, K>(
        msgs_sigs: T,
        params: &Params,
    ) -> bool
        where T: IntoIterator<Item = &'a K>,
              K: AsRef<[u8]> + AsRef<Signature> + AsRef<VerKey> + 'a {
        let mut aggr_sig = SignatureGroup::new();
        let mut hs: Vec<SignatureGroup> = Vec::new();
        let mut vs: Vec<&VerKey> = Vec::new();
        for msgs_sig in msgs_sigs {
            aggr_sig += &AsRef::<Signature>::as_ref(&msgs_sig).point;
            hs.push(Signature::hash_message(msgs_sig.as_ref()));
            vs.push(msgs_sig.as_ref());
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

impl AsRef<Signature> for Signature {
    fn as_ref(&self) -> &Signature { &self }
}

impl AsRef<Signature> for (Signature, VerKey) {
    fn as_ref(&self) -> &Signature { &self.0 }
}

impl AsRef<Signature> for (VerKey, Signature) {
    fn as_ref(&self) -> &Signature { &self.1 }
}

impl AsRef<VerKey> for (Signature, VerKey) {
    fn as_ref(&self) -> &VerKey { &self.1 }
}

impl AsRef<VerKey> for (VerKey, Signature) {
    fn as_ref(&self) -> &VerKey { &self.0 }
}

/// Contains a message of bytes, a Signature, and a VerKey
pub struct MessageSigAndVerKey {
    pub message: Vec<u8>,
    pub signature: Signature,
    pub ver_key: VerKey
}

impl MessageSigAndVerKey {
    pub fn new(message: Vec<u8>, signature: Signature, ver_key: VerKey) -> Self {
        Self { message, signature, ver_key }
    }
}

impl AsRef<[u8]> for MessageSigAndVerKey {
    fn as_ref(&self) -> &[u8] { &self.message }
}

impl AsRef<VerKey> for MessageSigAndVerKey {
    fn as_ref(&self) -> &VerKey { &self.ver_key }
}

impl AsRef<Signature> for MessageSigAndVerKey {
    fn as_ref(&self) -> &Signature { &self.signature }
}


#[cfg(test)]
mod tests {
    // TODO: Add tests for failure
    // TODO: Add more test vectors
    use super::*;
    use crate::common::Keypair;
    use rand::Rng;
    use rand::thread_rng;
    use std::time::Instant;

    #[test]
    fn sign_verify() {
        let mut rng = thread_rng();
        let params = Params::new("test".as_bytes());
        let keypair = Keypair::new(&mut rng, &params);
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
        let mut rng = thread_rng();
        let params = Params::new("test".as_bytes());
        let keypair = Keypair::new(&mut rng, &params);
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
        let mut rng = thread_rng();
        let params = Params::new("test".as_bytes());
        let keypair = Keypair::new(&mut rng, &params);
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
        let mut items: Vec<MessageSigAndVerKey> = Vec::new();
        let mut rng = rand::thread_rng();
        let count = 5;
        for _ in 0..count {
            let keypair = Keypair::new(&mut rng, &params);
            let msg = (0..10).map(|_| rng.gen_range(1, 100)).collect::<Vec<u8>>();
            let sig = Signature::new(&msg, &keypair.sig_key);
            items.push(MessageSigAndVerKey::new(msg, sig, keypair.ver_key));
        }

        let start = Instant::now();
        for i in 0..count {
            let item = &items[i];
            assert!(item.signature.verify(&item.message, &item.ver_key, &params));
        }
        println!(
            "Naive verify for {} sigs takes {:?}",
            count,
            start.elapsed()
        );

        let start = Instant::now();
        assert!(Signature::batch_verify(items.iter(), &params));
        println!(
            "Batch verify for {} sigs takes {:?}",
            count,
            start.elapsed()
        );

        let start = Instant::now();
        assert!(Signature::batch_verify_distinct_msgs(&items, &params));
        println!(
            "Batch verify assuming distinct messages for {} sigs takes {:?}",
            count,
            start.elapsed()
        );
    }
}
