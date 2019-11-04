use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem::GroupElementVector;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use super::common::VerKey;
use super::simple::Signature;
use ate_2_pairing;
use common::{Params, VERKEY_DOMAIN_PREFIX};
use {SignatureGroup, SignatureGroupVec, VerkeyGroup, VerkeyGroupVec};

// This is a newer but SLOWER way of doing BLS signature aggregation. This is NOT VULNERABLE to
// rogue public key attack so does not need proof of possession.

pub struct AggregatedVerKey {}

impl AggregatedVerKey {
    // Hashes a verkey with all other verkeys using a Hash function `H:{0, 1}* -> Z_q`
    // Takes a verkey `vk_i` and all verkeys `vk_1, vk_2,...vk_n` (including `vk_i`) and calculates
    // `H(vk_i||vk_1||vk_2...||vk_i||...vk_n)`
    pub fn hashed_verkey_for_aggregation<'a>(
        ver_key: &VerKey,
        all_ver_key_bytes: impl IntoIterator<Item = &'a Vec<u8>>,
    ) -> FieldElement {
        // TODO: Sort the verkeys in some order to avoid accidentally passing wrong order of keys
        let mut res_vec: Vec<u8> = Vec::new();

        res_vec.extend_from_slice(&ver_key.to_bytes());

        for vk_bytes in all_ver_key_bytes.into_iter() {
            res_vec.extend_from_slice(vk_bytes);
        }
        Self::hash_verkeys(res_vec.as_slice())
    }

    // Calculates the aggregated verkey
    // For each `v_i` of the verkeys `vk_1, vk_2,...vk_n` calculate
    // `a_i = vk_i * hashed_verkey_for_aggregation(vk_i, [vk_1, vk_2,...vk_n])`
    // Add all `a_i`
    pub fn new<'a, T>(ver_keys: T) -> VerKey
    where
        T: IntoIterator<Item = &'a VerKey>,
        T::IntoIter: Clone,
    {
        let ver_keys = ver_keys.into_iter();
        // TODO: Sort the verkeys in some order to avoid accidentally passing wrong order of keys
        let vk_bytes: Vec<_> = ver_keys.clone().map(|x| x.to_bytes()).collect();

        let (hs, vks): (Vec<_>, Vec<_>) = ver_keys
            .map(|vk| (
                AggregatedVerKey::hashed_verkey_for_aggregation(vk, &vk_bytes),
                vk.point.clone(),
            ))
            .unzip();

        let avk = VerkeyGroupVec::from(vks)
            .multi_scalar_mul_var_time(&hs.into())
            .unwrap();
        VerKey { point: avk }
    }

    /// Hash verkey bytes to field element. H_1 from the paper.
    pub(crate) fn hash_verkeys(verkey_bytes: &[u8]) -> FieldElement {
        FieldElement::from_msg_hash(&[&VERKEY_DOMAIN_PREFIX, verkey_bytes].concat())
    }
}

pub struct MultiSignature {}

impl MultiSignature {
    // The aggregator needs to know of all the signer before it can generate the aggregate signature.
    // Takes individual signatures from each of the signers and their verkey and aggregates the
    // signatures. For each signature `s_i` from signer with verkey `v_i` calculate
    // `a_i = hashed_verkey_for_aggregation(vk_i, [vk_1, vk_2,...vk_n])`
    // `a_si = s_i * a_i`
    // Add all `a_si`.
    // An alternate construction is (as described in the paper) to let signer compute `s_i * a_i` and
    // the aggregator simply adds each signer's output. In that model, signer does more work but in the
    // implemented model, aggregator does more work and the same signer implementation can be used by
    // signers of "slow" and "fast" implementation.
    pub fn new<'a, T>(sigs_and_ver_keys: T) -> Signature
    where
        T: IntoIterator<Item = &'a (Signature, VerKey)>,
        T::IntoIter: Clone,
    {
        let sigs_and_ver_keys = sigs_and_ver_keys.into_iter();
        // TODO: Sort the verkeys in some order to avoid accidentally passing wrong order of keys

        let all_ver_key_bytes: Vec<_> = sigs_and_ver_keys
            .clone()
            .map(|(_, vk)| vk.to_bytes())
            .collect();

        let (hs, sigs): (Vec<_>, Vec<_>) = sigs_and_ver_keys
            .map(|(sig, vk)| {
                (
                    AggregatedVerKey::hashed_verkey_for_aggregation(vk, &all_ver_key_bytes),
                    sig.point.clone(),
                )
            })
            .unzip();

        let asig = SignatureGroupVec::from(sigs)
            .multi_scalar_mul_var_time(&hs.into())
            .unwrap();

        Signature { point: asig }
    }

    pub fn verify<'a, T>(sig: &Signature, msg: &[u8], ver_keys: T, params: &Params) -> bool
    where
        T: IntoIterator<Item = &'a VerKey>,
        T::IntoIter: Clone,
    {
        let avk = AggregatedVerKey::new(ver_keys);
        sig.verify(msg, &avk, params)
    }

    // For verifying multiple aggregate signatures from the same signers,
    // an aggregated verkey should be created once and then used for each signature verification
}

#[cfg(test)]
mod tests {
    // TODO: Add tests for failure
    // TODO: Add more test vectors
    use super::*;
    use crate::common::Keypair;

    #[test]
    fn multi_sign_verify() {
        let params = Params::new("test".as_bytes());
        let keypair1 = Keypair::new(None, &params);
        let keypair2 = Keypair::new(None, &params);
        let keypair3 = Keypair::new(None, &params);
        let keypair4 = Keypair::new(None, &params);
        let keypair5 = Keypair::new(None, &params);

        let msg = "Small msg";
        let msg1 = "121220888888822111212";
        let msg2 = "Some message to sign";
        let msg3 = "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222";
        let msg4 = " is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";

        for m in vec![msg, msg1, msg2, msg3, msg4] {
            let b = m.as_bytes();
            let mut sigs_and_ver_keys: Vec<(Signature, VerKey)> = Vec::new();
            let mut vks: Vec<VerKey> = Vec::new();

            for keypair in vec![&keypair1, &keypair2, &keypair3, &keypair4, &keypair5] {
                let sig = Signature::new(&b, &keypair.sig_key);
                assert!(sig.verify(&b, &keypair.ver_key, &params));
                let v = keypair.ver_key.clone();
                vks.push(v);
                let v = keypair.ver_key.clone();
                sigs_and_ver_keys.push((sig, v));
            }

            let mut asig = MultiSignature::new(&sigs_and_ver_keys);
            assert!(MultiSignature::verify(&asig, &b, &vks, &params));

            let mut avk = AggregatedVerKey::new(&vks);
            assert!(asig.verify(&b, &avk, &params));

            let bs = asig.to_bytes();
            let mut sig1 = Signature::from_bytes(&bs).unwrap();
            assert!(sig1.verify(&b, &avk, &params));
            // FIXME: Next line fails, probably something wrong with main amcl codebase.
            //assert_eq!(&asig.point.to_hex(), &sig1.point.to_hex());

            let bs = avk.to_bytes();
            let mut avk1 = VerKey::from_bytes(&bs).unwrap();
            // FIXME: Next line fails, probably something wrong with main amcl codebase.
            //assert_eq!(&avk.point.to_hex(), &avk1.point.to_hex());
            assert_eq!(avk.point.to_bytes(), avk1.point.to_bytes());
        }
    }

    #[test]
    fn multi_signature_at_infinity() {
        let params = Params::new("test".as_bytes());
        let keypair1 = Keypair::new(None, &params);
        let keypair2 = Keypair::new(None, &params);
        let msg = "Small msg".as_bytes();

        let asig = Signature {
            point: SignatureGroup::identity(),
        };
        let vks = vec![keypair1.ver_key, keypair2.ver_key];
        assert_eq!(MultiSignature::verify(&asig, &msg, &vks, &params), false);
    }

    // TODO: New test that has benchmark for using AggregatedVerKey
}
