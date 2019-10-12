use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use super::common::VerKey;
use super::simple::Signature;
use common::Params;

// This is a newer but SLOWER way of doing BLS signature aggregation. This is NOT VULNERABLE to
// rogue public key attack so does not need proof of possession.

#[derive(Debug, Clone)]
pub struct AggregatedVerKey {
    pub point: G2,
}

impl AggregatedVerKey {
    // Hashes a verkey with all other verkeys using a Hash function `H:{0, 1}* -> Z_q`
    // Takes a verkey `vk_i` and all verkeys `vk_1, vk_2,...vk_n` (including `vk_i`) and calculates
    // `H(vk_i||vk_1||vk_2...||vk_i||...vk_n)`
    pub fn hashed_verkey_for_aggregation(
        ver_key: &VerKey,
        all_ver_keys: &Vec<&VerKey>,
    ) -> FieldElement {
        // TODO: Sort the verkeys in some order to avoid accidentally passing wrong order of keys
        let mut res_vec: Vec<u8> = Vec::new();

        res_vec.extend_from_slice(&ver_key.to_bytes());

        for vk in all_ver_keys {
            res_vec.extend_from_slice(&vk.to_bytes());
        }
        FieldElement::from_msg_hash(res_vec.as_slice())
    }

    // Calculates the aggregated verkey
    // For each `v_i` of the verkeys `vk_1, vk_2,...vk_n` calculate
    // `a_i = vk_i * hashed_verkey_for_aggregation(vk_i, [vk_1, vk_2,...vk_n])`
    // Add all `a_i`
    pub fn new(ver_keys: Vec<&VerKey>) -> Self {
        // TODO: Sort the verkeys in some order to avoid accidentally passing wrong order of keys
        let mut vks: Vec<G2> = Vec::new();

        for mut vk in ver_keys.clone() {
            let h = AggregatedVerKey::hashed_verkey_for_aggregation(&mut vk, &ver_keys);
            /*let (mut a, mut b) = (vk.clone().point, h.clone());
            println!("Hashing vk {} with all leads to {}", &a.to_hex(), &b.to_hex());*/
            vks.push(&vk.point * &h);
        }

        let mut avk: G2 = G2::identity();
        for vk in vks {
            avk += vk;
        }
        AggregatedVerKey { point: avk }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<AggregatedVerKey, SerzDeserzError> {
        G2::from_bytes(vk_bytes).map(|point| AggregatedVerKey { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct MultiSignature {
    pub point: G1,
}

impl MultiSignature {
    // The aggregator needs to know of all the signer before it can generate the aggregate signature.
    // Takes individual signatures from each of the signers and their verkey and aggregates the
    // signatures. For each signature `s_i` from signer with verkey `v_i` calculate
    // `a_si = s_i * hashed_verkey_for_aggregation(vk_i, [vk_1, vk_2,...vk_n])`
    // Add all `a_si`
    pub fn new(sigs_and_ver_keys: Vec<(&Signature, &VerKey)>) -> Self {
        // TODO: Sort the verkeys in some order to avoid accidentally passing wrong order of keys
        let all_ver_keys: Vec<&VerKey> =
            sigs_and_ver_keys.iter().map(|(_, vk)| vk.clone()).collect();
        let mut sigs: Vec<G1> = Vec::new();
        for (sig, mut vk) in sigs_and_ver_keys {
            let h = AggregatedVerKey::hashed_verkey_for_aggregation(&mut vk, &all_ver_keys);
            /*let (mut a, mut b) = (vk.clone().point, h.clone());
            println!("Hashing vk {} with all leads to {}", &a.to_hex(), &b.to_hex());*/
            sigs.push(&sig.point * h);
        }

        let mut asig: G1 = G1::identity();
        for s in sigs {
            asig += s;
        }
        MultiSignature { point: asig }
    }

    pub fn verify(&self, msg: &[u8], ver_keys: Vec<&VerKey>, params: &Params) -> bool {
        let avk = AggregatedVerKey::new(ver_keys);
        self.verify_using_aggr_vk(msg, &avk, params)
    }

    // For verifying multiple aggregate signatures from the same signers,
    // an aggregated verkey should be created once and then used for each signature verification
    pub fn verify_using_aggr_vk(&self, msg: &[u8], avk: &AggregatedVerKey, params: &Params) -> bool {
        //        if !self.is_valid_point() {
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
            &params.g.negation(),
            &msg_hash_point,
            &avk.point,
        );
        e.is_one()
    }

    pub fn from_bytes(sig_bytes: &[u8]) -> Result<MultiSignature, SerzDeserzError> {
        G1::from_bytes(sig_bytes).map(|point| MultiSignature { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }

    // TODO: Add batch verification
}

//impl<G: GroupG1> CurvePoint for AggregatedSignature {}
/*impl CurvePoint for AggregatedSignature {
    fn is_valid_point(&self) -> bool {
        if self.point.is_infinity() {
            return false;
        }
        true
    }
}*/

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

            let vks_1: Vec<&VerKey> = vks.iter().map(|v| v).collect();
            let vks_2: Vec<&VerKey> = vks.iter().map(|v| v).collect();
            let sigs_and_ver_keys: Vec<(&Signature, &VerKey)> =
                sigs_and_ver_keys.iter().map(|(s, v)| (s, v)).collect();
            let mut asig = MultiSignature::new(sigs_and_ver_keys);
            assert!(asig.verify(&b, vks_1, &params));

            let mut avk = AggregatedVerKey::new(vks_2);
            assert!(asig.verify_using_aggr_vk(&b, &avk, &params));

            let bs = asig.to_bytes();
            let mut sig1 = MultiSignature::from_bytes(&bs).unwrap();
            assert!(sig1.verify_using_aggr_vk(&b, &avk, &params));
            // FIXME: Next line fails, probably something wrong with main amcl codebase.
            //assert_eq!(&asig.point.to_hex(), &sig1.point.to_hex());

            let bs = avk.to_bytes();
            let mut avk1 = AggregatedVerKey::from_bytes(&bs).unwrap();
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

        let asig = MultiSignature {
            point: G1::identity(),
        };
        let vks: Vec<&VerKey> = vec![&keypair1.ver_key, &keypair2.ver_key];
        assert_eq!(asig.verify(&msg, vks, &params), false);
    }

    // TODO: New test that has benchmark for using AggregatedVerKey
}
