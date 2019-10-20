use crate::{SignatureGroupVec, VerkeyGroupVec};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::GroupElementVector;
use common::{Params, SigKey, VerKey};
use secret_sharing::polynomial::Polynomial;
use secret_sharing::shamir_secret_sharing::get_shared_secret;
use simple::Signature;
use std::collections::{HashMap, HashSet};

pub struct Signer {
    pub id: usize,
    pub sigkey: SigKey,
    pub verkey: VerKey,
}

/// Takes shares for x and generate signing and verification keys
fn keygen_from_shares(
    num_signers: usize,
    mut x_shares: HashMap<usize, FieldElement>,
    params: &Params,
) -> Vec<Signer> {
    let mut signers = vec![];
    for i in 0..num_signers {
        let id = i + 1;
        let x_i = x_shares.remove(&id).unwrap();
        let g_x_i = &params.g * &x_i;

        signers.push(Signer {
            id,
            sigkey: SigKey { x: x_i },
            verkey: VerKey { point: g_x_i },
        })
    }
    signers
}

/// Keygen done by trusted party using Shamir secret sharing. Creates signing and verification
/// keys for each signer. The trusted party will know every signer's secret keys and the
/// aggregate secret keys and can create signatures.
/// Outputs 2 items, first is the shared secret and should be destroyed.
/// The second contains the keys, 1 item corresponding to each signer.
pub fn trusted_party_SSS_keygen(
    threshold: usize,
    total: usize,
    params: &Params,
) -> (FieldElement, Vec<Signer>) {
    let (secret_x, x_shares) = get_shared_secret(threshold, total);
    (secret_x, keygen_from_shares(total, x_shares, params))
}

pub struct ThresholdScheme {}

impl ThresholdScheme {
    pub fn aggregate_sigs(threshold: usize, sigs: Vec<(usize, Signature)>) -> Signature {
        assert!(sigs.len() >= threshold);
        let mut s_bases = SignatureGroupVec::with_capacity(threshold);
        let mut s_exps = FieldElementVector::with_capacity(threshold);

        let signer_ids = sigs
            .iter()
            .take(threshold)
            .map(|(i, _)| *i)
            .collect::<HashSet<usize>>();
        for (id, sig) in sigs.into_iter().take(threshold) {
            let l = Polynomial::lagrange_basis_at_0(signer_ids.clone(), id);
            s_bases.push(sig.point.clone());
            s_exps.push(l);
        }
        // theshold signature = sig[i]^l for all i
        Signature {
            point: s_bases.multi_scalar_mul_const_time(&s_exps).unwrap(),
        }
    }

    pub fn aggregate_vk(threshold: usize, keys: Vec<(usize, &VerKey)>) -> VerKey {
        assert!(keys.len() >= threshold);

        let mut vk_bases = VerkeyGroupVec::with_capacity(threshold);
        let mut vk_exps = FieldElementVector::with_capacity(threshold);

        let signer_ids = keys
            .iter()
            .take(threshold)
            .map(|(i, _)| *i)
            .collect::<HashSet<usize>>();
        for (id, vk) in keys.into_iter().take(threshold) {
            let l = Polynomial::lagrange_basis_at_0(signer_ids.clone(), id);
            vk_bases.push(vk.point.clone());
            vk_exps.push(l.clone());
        }

        // threshold verkey = vk_1^l_1 * vk_2^l_2 * ... vk_i^l_i for i in threshold

        VerKey {
            point: vk_bases.multi_scalar_mul_var_time(&vk_exps).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_threshold_key_gen(
        threshold: usize,
        secret_x: FieldElement,
        signers: &[Signer],
        params: &Params,
    ) {
        let threshold_vk = ThresholdScheme::aggregate_vk(
            threshold,
            signers
                .iter()
                .take(threshold)
                .map(|s| (s.id, &s.verkey))
                .collect::<Vec<(usize, &VerKey)>>(),
        );

        let expected_vk = &params.g * &secret_x;
        assert_eq!(expected_vk, threshold_vk.point);
    }

    fn check_signing_on_random_msgs(threshold: usize, signers: &[Signer], params: &Params) {
        let msg = FieldElement::random().to_bytes();

        let mut sigs = vec![];
        for i in 0..threshold {
            let sig = Signature::new(&msg, &signers[i].sigkey);
            assert!(sig.verify(&msg, &signers[i].verkey, &params));
            sigs.push((signers[i].id, sig));
        }

        let threshold_sig = ThresholdScheme::aggregate_sigs(threshold, sigs);

        let threshold_vk = ThresholdScheme::aggregate_vk(
            threshold,
            signers
                .iter()
                .map(|s| (s.id, &s.verkey))
                .collect::<Vec<(usize, &VerKey)>>(),
        );

        assert!(threshold_sig.verify(&msg, &threshold_vk, &params));
    }

    fn check_threshold_key_gen_gaps_in_ids(
        threshold: usize,
        secret_x: FieldElement,
        keys_to_aggr: Vec<(usize, &VerKey)>,
        params: &Params,
    ) {
        let threshold_vk = ThresholdScheme::aggregate_vk(threshold, keys_to_aggr);

        let expected_vk = &params.g * &secret_x;
        assert_eq!(expected_vk, threshold_vk.point);
    }

    #[test]
    fn test_verkey_aggregation_shamir_secret_sharing_keygen() {
        let threshold = 3;
        let total = 5;
        let params = Params::new("test".as_bytes());

        let (secret_x, signers) = trusted_party_SSS_keygen(threshold, total, &params);

        check_threshold_key_gen(threshold, secret_x, &signers, &params)
    }

    #[test]
    fn test_sign_verify_shamir_secret_sharing_keygen() {
        let threshold = 3;
        let total = 5;
        let params = Params::new("test".as_bytes());

        let (_, signers) = trusted_party_SSS_keygen(threshold, total, &params);

        check_signing_on_random_msgs(threshold, &signers, &params)
    }

    #[test]
    fn test_verkey_aggregation_gaps_in_ids_shamir_secret_sharing_keygen() {
        let threshold = 3;
        let total = 5;
        let params = Params::new("test".as_bytes());
        let (secret_x, signers) = trusted_party_SSS_keygen(threshold, total, &params);

        let mut keys = vec![];
        keys.push((signers[0].id, &signers[0].verkey));
        keys.push((signers[2].id, &signers[2].verkey));
        keys.push((signers[4].id, &signers[4].verkey));

        check_threshold_key_gen_gaps_in_ids(threshold, secret_x, keys, &params);
    }

    #[test]
    fn test_sign_verify_1() {
        // Request signature from 1 threshold group of signers and form aggregate verkey from
        // different threshold group of signers.
        let threshold = 3;
        let total = 6;
        let params = Params::new("test".as_bytes());
        let (_, signers) = trusted_party_SSS_keygen(threshold, total, &params);

        let msg = FieldElement::random().to_bytes();

        // Signers from which signature will be requested.
        let mut signer_ids = HashSet::new();
        signer_ids.insert(1);
        signer_ids.insert(3);
        signer_ids.insert(5);

        let mut sigs = vec![];
        for i in &signer_ids {
            let sig = Signature::new(&msg, &signers[*i].sigkey);
            assert!(sig.verify(&msg, &signers[*i].verkey, &params));
            sigs.push((signers[*i].id, sig));
        }

        let threshold_sig = ThresholdScheme::aggregate_sigs(threshold, sigs);

        let mut keys = vec![];
        keys.push((signers[1].id, &signers[1].verkey)); // signer id is 2
        keys.push((signers[3].id, &signers[3].verkey)); // signer id is 4
        keys.push((signers[5].id, &signers[5].verkey)); // signer id is 6

        let threshold_vk = ThresholdScheme::aggregate_vk(threshold, keys);

        assert!(threshold_sig.verify(&msg, &threshold_vk, &params));
    }

    // TODO: Add tests for cases when threshold is not met
}
