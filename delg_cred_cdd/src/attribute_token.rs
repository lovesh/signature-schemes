// A presenter is an entity holding a CredChain which does proof of attribute tokens

use crate::errors::{DelgError, DelgResult};
use crate::groth_sig::{Groth1SetupParams, Groth1Sig, Groth1Verkey, Groth2SetupParams, Groth2Sig};
use crate::issuer::{CredChain, EvenLevelVerkey, OddLevelVerkey};
use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};
use std::collections::{HashMap, HashSet};

pub type OddLevelAttribute = G1;
pub type EvenLevelAttribute = G2;

pub struct AttributeToken {}

pub struct AttributeTokenComm {
    pub odd_level_blinded_sigs: Vec<Groth1Sig>,
    pub even_level_blinded_sigs: Vec<Groth2Sig>,
    pub comms: Vec<Vec<GT>>,
    pub blindings_sigs: FieldElementVector,
    pub blindings_vk: FieldElementVector,
    pub blindings_s: FieldElementVector,
    pub blindings_t: Vec<FieldElementVector>,
    pub blindings_a: Vec<FieldElementVector>,
    pub odd_level_revealed_attributes: Vec<HashMap<usize, OddLevelAttribute>>,
    pub even_level_revealed_attributes: Vec<HashMap<usize, EvenLevelAttribute>>,
}

pub struct AttributeTokenResp {
    pub odd_level_blinded_r: G2Vector,
    pub even_level_blinded_r: G1Vector,
    pub resp_csk: FieldElement,
    pub odd_level_resp_vk: G1Vector,
    pub even_level_resp_vk: G2Vector,
    pub odd_level_resp_s: G1Vector,
    pub even_level_resp_s: G2Vector,
    pub odd_level_resp_t: Vec<G1Vector>,
    pub even_level_resp_t: Vec<G2Vector>,
    pub odd_level_resp_a: Vec<G1Vector>,
    pub even_level_resp_a: Vec<G2Vector>,
    pub odd_level_revealed_attributes: Vec<HashMap<usize, OddLevelAttribute>>,
    pub even_level_revealed_attributes: Vec<HashMap<usize, EvenLevelAttribute>>,
}

impl AttributeToken {
    // TODO: Provide a method that takes precomputed e(g, r_i), e(g1, -g2), e(-g1, g2), e(y_{1, j}, g2), e(g1, y_{2, j})
    // Assuming that chain has already been verified using `CredChain::verify_delegations`
    pub fn comm_phase(
        cred_chain: &CredChain,
        revealed: Vec<HashSet<usize>>,
        setup_params_1: &Groth1SetupParams,
        setup_params_2: &Groth2SetupParams,
    ) -> DelgResult<AttributeTokenComm> {
        let L = cred_chain.size();
        assert_eq!(revealed.len(), L);

        // In practice, g1 and g2 in both Groth1 and Groth2 can be same
        let groth1_neg_g1 = setup_params_1.g1.negation();
        let groth2_neg_g1 = setup_params_2.g1.negation();

        // e(-g1, g2), e(g1, -g2) are needed at several places for Groth1 and Groth2. But e(-g1, g2) and e(g1, -g2) are equal and same as e(g1, g2)^-1.
        // Not computing e(g1, g2)^-1 as computing inverse is more expensive than negating any group element
        // In practice, e(g1, g2)^-1 in both Groth1 and Groth2 can be same
        // For Groth1 params e(-g1, g2) == e(g1, -g2) == e(g1, g2)^-1
        let pairing_inv_groth1_g1_g2 = GT::ate_pairing(&groth1_neg_g1, &setup_params_1.g2);
        // For Groth2 params e(-g1, g2) == e(g1, -g2) == e(g1, g2)^-1
        let pairing_inv_groth2_g1_g2 = GT::ate_pairing(&groth2_neg_g1, &setup_params_2.g2);

        let mut blindings_sigs = FieldElementVector::with_capacity(L);
        let mut blindings_vk = FieldElementVector::with_capacity(L);
        let mut blindings_s = FieldElementVector::with_capacity(L);
        let mut blindings_t = Vec::<FieldElementVector>::with_capacity(L);
        let mut blindings_a = Vec::<FieldElementVector>::with_capacity(L);

        let mut odd_level_revealed_attributes =
            Vec::<HashMap<usize, OddLevelAttribute>>::with_capacity(L);
        let mut even_level_revealed_attributes =
            Vec::<HashMap<usize, EvenLevelAttribute>>::with_capacity(L);
        let mut odd_level_blinded_sigs = vec![];
        let mut even_level_blinded_sigs = vec![];
        let mut comms = Vec::<Vec<GT>>::with_capacity(L);

        for i in 1..=L {
            let rho_sig = FieldElement::random();
            let rho_s = FieldElement::random();
            let rho_vk = FieldElement::random();

            let (rho_t, rho_a, com_t) = if i % 2 == 1 {
                // Odd levels
                let link = cred_chain.get_odd_link(i / 2)?;
                odd_level_blinded_sigs.push(link.signature.randomize(&rho_sig));

                let mut rev_attrs = HashMap::<usize, OddLevelAttribute>::new();

                // e(g1, ri)
                let pairing_g1_ri = GT::ate_pairing(&setup_params_1.g1, &link.signature.R);

                let com_i_s = if i == 1 {
                    // e(g1, ri)^{rho_sig*rho_s}
                    GT::pow(&pairing_g1_ri, &(&rho_sig * &rho_s))
                } else {
                    // e(g1, ri)^{rho_sig*rho_s} * e(-g1, g2)^{blindings_vk[i-2]}
                    let e_1 = GT::pow(&pairing_g1_ri, &(&rho_sig * &rho_s));
                    let e_2 = GT::pow(&pairing_inv_groth1_g1_g2, &blindings_vk[i - 2]);
                    GT::mul(&e_1, &e_2)
                };

                let unrevealed_attr_count = link.message_count() - revealed[i - 1].len();
                let mut r_t = FieldElementVector::with_capacity(link.message_count());
                let mut r_a = FieldElementVector::with_capacity(unrevealed_attr_count);
                let mut com_t = Vec::<GT>::with_capacity(link.message_count());

                // Last attribute is the verkey so skip for now
                for j in 0..(link.message_count() - 1) {
                    // blinding for t_{i, j}
                    let rr_t = FieldElement::random();

                    let mut com_i_t = if i == 1 {
                        // e(g1, ri)^{rho_sig*rr_t}
                        GT::pow(&pairing_g1_ri, &(&rho_sig * &rr_t))
                    } else {
                        // e(g1, ri)^{rho_sig*rr_t} * e(y1_j, g2)^{blindings_vk[i-2]}
                        let e_1 = GT::pow(&pairing_g1_ri, &(&rho_sig * &rr_t));
                        let e_2 = GT::ate_pairing(&setup_params_1.y[j], &setup_params_1.g2);
                        let e_3 = GT::pow(&e_2, &blindings_vk[i - 2]);
                        GT::mul(&e_1, &e_3)
                    };

                    if !revealed[i - 1].contains(&j) {
                        // Unrevealed attribute
                        // e(g1, ri)^{rho_sig*rr_t} * e(y1_j, g2)^{blindings_vk[i-2]} * e(-g1, g2)^rr_a
                        let rr_a = FieldElement::random();
                        let e = GT::pow(&pairing_inv_groth1_g1_g2, &rr_a);
                        com_i_t = GT::mul(&com_i_t, &e);
                        r_a.push(rr_a);
                    } else {
                        rev_attrs.insert(j, link.messages[j].clone());
                    }
                    com_t.push(com_i_t);
                    r_t.push(rr_t);
                }

                odd_level_revealed_attributes.push(rev_attrs);

                // For verkey
                let rr_t = FieldElement::random();
                let mut com_i_vk = {
                    // e(g1, ri)^{rho_sig*rr_t} * e(-g1, g2)^rr_a
                    let e_1 = GT::pow(&pairing_g1_ri, &(&rho_sig * &rr_t));
                    let e_2 = GT::pow(&pairing_inv_groth1_g1_g2, &rho_vk);
                    GT::mul(&e_1, &e_2)
                };
                if i != 1 {
                    // e(g1, ri)^{rho_sig*rr_t} * e(-g1, g2)^rr_a * e(y1_j, g2)^{blindings_vk[i-2]}
                    let e_1 = GT::ate_pairing(
                        &setup_params_1.y[link.message_count() - 1],
                        &setup_params_1.g2,
                    );
                    let e_2 = GT::pow(&e_1, &blindings_vk[i - 2]);
                    com_i_vk = GT::mul(&com_i_vk, &e_2);
                }
                com_t.push(com_i_vk);
                r_t.push(rr_t);
                (r_t, r_a, com_t)
            } else {
                // Even levels
                let link = cred_chain.get_even_link((i / 2) - 1)?;
                even_level_blinded_sigs.push(link.signature.randomize(&rho_sig));

                let mut rev_attrs = HashMap::<usize, EvenLevelAttribute>::new();

                // e(ri, g2)
                let pairing_ri_g2 = GT::ate_pairing(&link.signature.R, &setup_params_2.g2);

                // e(ri, g2)^{rho_sig*rho_s} * e(-g1, g2)^{blindings_vk[i-2]}
                let e_1 = GT::pow(&pairing_ri_g2, &(&rho_sig * &rho_s));
                let e_2 = GT::pow(&pairing_inv_groth2_g1_g2, &blindings_vk[i - 2]);
                let com_i_s = GT::mul(&e_1, &e_2);

                let unrevealed_attr_count = link.message_count() - revealed[i - 1].len();
                let mut r_t = FieldElementVector::with_capacity(link.message_count());
                let mut r_a = FieldElementVector::with_capacity(unrevealed_attr_count);
                let mut com_t = Vec::<GT>::with_capacity(link.message_count());

                // Last attribute is the verkey so skip for now
                for j in 0..(link.message_count() - 1) {
                    // blinding for t_{i, j}
                    let rr_t = FieldElement::random();

                    // e(ri, g2)^{rho_sig*rr_t} * e(g1, y2_j)^{blindings_vk[i-2]}
                    let e_1 = GT::pow(&pairing_ri_g2, &(&rho_sig * &rr_t));
                    let e_2 = GT::ate_pairing(&setup_params_2.g1, &setup_params_2.y[j]);
                    let e_3 = GT::pow(&e_2, &blindings_vk[i - 2]);
                    let mut com_i_t = GT::mul(&e_1, &e_3);

                    if !revealed[i - 1].contains(&j) {
                        // Unrevealed attribute
                        // e(ri, g2)^{rho_sig*rr_t} * e(g1, y2_j)^{blindings_vk[i-2]} * e(-g1, g2)^rr_a
                        let rr_a = FieldElement::random();
                        let e = GT::pow(&pairing_inv_groth2_g1_g2, &rr_a);
                        com_i_t = GT::mul(&com_i_t, &e);
                        r_a.push(rr_a);
                    } else {
                        rev_attrs.insert(j, link.messages[j].clone());
                    }
                    com_t.push(com_i_t);
                    r_t.push(rr_t);
                }

                even_level_revealed_attributes.push(rev_attrs);

                // For verkey
                let rr_t = FieldElement::random();
                // e(ri, g2)^{rho_sig*rr_t} * e(-g1, g2)^rr_a * e(g1, y2_j)^{blindings_vk[i-2]}
                let e_1 = GT::pow(&pairing_ri_g2, &(&rho_sig * &rr_t));
                let e_2 = GT::pow(&pairing_inv_groth1_g1_g2, &rho_vk);
                let e_3 = GT::ate_pairing(
                    &setup_params_2.g1,
                    &setup_params_2.y[link.message_count() - 1],
                );
                let e_4 = GT::pow(&e_3, &blindings_vk[i - 2]);
                let com_i_vk = GT::mul(&GT::mul(&e_1, &e_2), &e_4);

                com_t.push(com_i_vk);
                r_t.push(rr_t);

                (r_t, r_a, com_t)
            };

            blindings_sigs.push(rho_sig);
            blindings_s.push(rho_s);
            blindings_vk.push(rho_vk);
            blindings_t.push(rho_t);
            blindings_a.push(rho_a);
            comms.push(com_t);
        }
        Ok(AttributeTokenComm {
            odd_level_blinded_sigs,
            even_level_blinded_sigs,
            comms,
            blindings_sigs,
            blindings_vk,
            blindings_s,
            blindings_t,
            blindings_a,
            odd_level_revealed_attributes,
            even_level_revealed_attributes,
        })
    }

    pub fn resp_phase(
        cred_chain: &CredChain,
        at: AttributeTokenComm,
        sig_key: &FieldElement,
        challenge: &FieldElement,
        even_level_vks: Vec<&EvenLevelVerkey>,
        odd_level_vks: Vec<&OddLevelVerkey>,
        setup_params_1: &Groth1SetupParams,
        setup_params_2: &Groth2SetupParams,
    ) -> DelgResult<AttributeTokenResp> {
        let L = at.blindings_sigs.len();
        assert_eq!(at.comms.len(), L);
        assert_eq!(at.blindings_vk.len(), L);
        assert_eq!(at.blindings_s.len(), L);
        assert_eq!(at.blindings_t.len(), L);
        assert_eq!(at.blindings_a.len(), L);
        assert_eq!(
            at.odd_level_blinded_sigs.len() + at.even_level_blinded_sigs.len(),
            L
        );
        assert_eq!(
            at.odd_level_revealed_attributes.len() + at.even_level_revealed_attributes.len(),
            L
        );

        let mut resp_csk = FieldElement::zero();
        let mut odd_level_resp_vk = G1Vector::new(0);
        let mut even_level_resp_vk = G2Vector::new(0);
        let mut odd_level_resp_s = G1Vector::new(0);
        let mut even_level_resp_s = G2Vector::new(0);
        let mut odd_level_resp_t = Vec::<G1Vector>::new();
        let mut even_level_resp_t = Vec::<G2Vector>::new();
        let mut odd_level_resp_a = Vec::<G1Vector>::new();
        let mut even_level_resp_a = Vec::<G2Vector>::new();

        for i in 1..=L {
            if i % 2 == 1 {
                let link = cred_chain.get_odd_link(i / 2)?;

                odd_level_resp_s.push(setup_params_1.g1.binary_scalar_mul(
                    &link.signature.S,
                    &at.blindings_s[i - 1],
                    challenge,
                ));

                if i != L {
                    odd_level_resp_vk.push(setup_params_1.g1.binary_scalar_mul(
                        &odd_level_vks[i / 2].0,
                        &at.blindings_vk[i - 1],
                        challenge,
                    ));
                } else {
                    resp_csk = &at.blindings_vk[i - 1] + (challenge * sig_key);
                }

                // Total messages - revealed attributes - last message (for verkey)
                let unrevealed_attr_count =
                    link.message_count() - at.odd_level_revealed_attributes[i / 2].len() - 1;
                assert_eq!(at.blindings_t[i - 1].len(), link.signature.T.len());
                assert_eq!(link.message_count(), link.signature.T.len());
                assert_eq!(at.blindings_a[i - 1].len(), unrevealed_attr_count);
                let mut resp_t = G1Vector::with_capacity(link.message_count());
                let mut resp_a = G1Vector::with_capacity(unrevealed_attr_count);
                let mut k = 0;
                for j in 0..link.message_count() {
                    resp_t.push(setup_params_1.g1.binary_scalar_mul(
                        &link.signature.T[j],
                        &at.blindings_t[i - 1][j],
                        challenge,
                    ));
                    // If attribute is not revealed. Last attribute is verkey so ignore.
                    if j != (link.message_count() - 1)
                        && !at.odd_level_revealed_attributes[i / 2].contains_key(&j)
                    {
                        resp_a.push(setup_params_1.g1.binary_scalar_mul(
                            &link.messages[j],
                            &at.blindings_a[i - 1][k],
                            challenge,
                        ));
                        k += 1;
                    }
                }
                debug_assert_eq!(resp_a.len(), unrevealed_attr_count);

                odd_level_resp_t.push(resp_t);
                odd_level_resp_a.push(resp_a);
            } else {
                let link = cred_chain.get_even_link((i / 2) - 1)?;

                even_level_resp_s.push(binary_scalar_mul_g2(
                    &setup_params_2.g2,
                    &link.signature.S,
                    &at.blindings_s[i - 1],
                    challenge,
                ));

                if i != L {
                    even_level_resp_vk.push(binary_scalar_mul_g2(
                        &setup_params_2.g2,
                        &even_level_vks[(i / 2) - 1].0,
                        &at.blindings_vk[i - 1],
                        challenge,
                    ));
                } else {
                    resp_csk = &at.blindings_vk[i - 1] + (challenge * sig_key);
                }

                // Total messages - revealed attributes - last message (for verkey)
                let unrevealed_attr_count =
                    link.message_count() - at.even_level_revealed_attributes[(i / 2) - 1].len() - 1;
                assert_eq!(at.blindings_t[i - 1].len(), link.signature.T.len());
                assert_eq!(link.message_count(), link.signature.T.len());
                assert_eq!(at.blindings_a[i - 1].len(), unrevealed_attr_count);
                let mut resp_t = G2Vector::with_capacity(link.message_count());
                let mut resp_a = G2Vector::with_capacity(unrevealed_attr_count);
                let mut k = 0;
                for j in 0..link.message_count() {
                    resp_t.push(binary_scalar_mul_g2(
                        &setup_params_2.g2,
                        &link.signature.T[j],
                        &at.blindings_t[i - 1][j],
                        challenge,
                    ));
                    // If attribute is not revealed. Last attribute is verkey so ignore.
                    if j != (link.message_count() - 1)
                        && !at.even_level_revealed_attributes[(i / 2) - 1].contains_key(&j)
                    {
                        resp_a.push(binary_scalar_mul_g2(
                            &setup_params_2.g2,
                            &link.messages[j],
                            &at.blindings_a[i - 1][k],
                            challenge,
                        ));
                        k += 1;
                    }
                }
                debug_assert_eq!(resp_a.len(), unrevealed_attr_count);

                even_level_resp_t.push(resp_t);
                even_level_resp_a.push(resp_a);
            }
        }

        let odd_level_blinded_r: G2Vector = at.odd_level_blinded_sigs.iter().map(|sig| sig.R.clone()).collect::<Vec<G2>>().into();
        let even_level_blinded_r: G1Vector = at.even_level_blinded_sigs.iter().map(|sig| sig.R.clone()).collect::<Vec<G1>>().into();

        Ok(AttributeTokenResp {
            odd_level_blinded_r,
            even_level_blinded_r,
            resp_csk,
            odd_level_resp_vk,
            even_level_resp_vk,
            odd_level_resp_s,
            even_level_resp_s,
            odd_level_resp_t,
            even_level_resp_t,
            odd_level_resp_a,
            even_level_resp_a,
            odd_level_revealed_attributes: at.odd_level_revealed_attributes,
            even_level_revealed_attributes: at.even_level_revealed_attributes,
        })
    }

    pub fn gen_challenge(at: &AttributeTokenComm) -> FieldElement {
        let mut bytes = Vec::<u8>::new();
        unimplemented!()
    }

    // TODO: Create a verify_fast that does a single multi-pairing like verify_fast in GrothSig
    pub fn verify(
        proof: &AttributeTokenResp,
        revealed: Vec<HashSet<usize>>,
        challenge: &FieldElement,
        ipk: &Groth1Verkey,
        setup_params_1: &Groth1SetupParams,
        setup_params_2: &Groth2SetupParams,
    ) -> DelgResult<bool> {
        unimplemented!()
    }
}

/// XXX: Temporary until binary_scalar_mul is added to G2
fn binary_scalar_mul_g2(g2: &G2, h2: &G2, r1: &FieldElement, r2: &FieldElement) -> G2 {
    let mut g2_vec = G2Vector::with_capacity(2);
    g2_vec.push(g2.clone());
    g2_vec.push(h2.clone());
    let mut f_vec = FieldElementVector::with_capacity(2);
    f_vec.push(r1.clone());
    f_vec.push(r2.clone());
    g2_vec.multi_scalar_mul_const_time(&f_vec).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use crate::groth_sig::{GrothS1, GrothS2};
    use crate::issuer::{EvenLevelIssuer, OddLevelIssuer};
    use amcl_wrapper::group_elem_g1::G1Vector;
    use amcl_wrapper::group_elem_g2::G2Vector;
    use std::time::{Duration, Instant};

    #[test]
    fn test_attribute_token() {
        let max_attributes = 5;
        let label = "test".as_bytes();

        let params1 = GrothS1::setup(max_attributes, label);
        let params2 = GrothS2::setup(max_attributes, label);

        let l_0_issuer = EvenLevelIssuer::new(0).unwrap();
        let l_1_issuer = OddLevelIssuer::new(1).unwrap();
        let l_2_issuer = EvenLevelIssuer::new(2).unwrap();
        let l_3_issuer = OddLevelIssuer::new(3).unwrap();

        let (l_0_issuer_sk, l_0_issuer_vk) = EvenLevelIssuer::keygen(&params1);
        let (l_1_issuer_sk, l_1_issuer_vk) = OddLevelIssuer::keygen(&params2);
        let (l_2_issuer_sk, l_2_issuer_vk) = EvenLevelIssuer::keygen(&params1);
        let (l_3_issuer_sk, l_3_issuer_vk) = OddLevelIssuer::keygen(&params2);
        let (l_4_issuer_sk, l_4_issuer_vk) = EvenLevelIssuer::keygen(&params1);

        let attributes_1: G1Vector = (0..max_attributes - 1)
            .map(|_| G1::random())
            .collect::<Vec<G1>>()
            .into();
        let cred_link_1 = l_0_issuer
            .delegate(
                attributes_1.clone(),
                l_1_issuer_vk.clone(),
                &l_0_issuer_sk,
                &params1,
            )
            .unwrap();
        let mut chain_1 = CredChain::new();
        chain_1.extend_with_odd(cred_link_1).unwrap();

        let com_1 = AttributeToken::comm_phase(
            &chain_1,
            vec![HashSet::<usize>::new(); 1],
            &params1,
            &params2,
        )
        .unwrap();
        let c_1 = FieldElement::random();
        let resp_1 = AttributeToken::resp_phase(
            &chain_1,
            com_1,
            &l_1_issuer_sk.0,
            &c_1,
            vec![],
            vec![&l_1_issuer_vk],
            &params1,
            &params2,
        )
        .unwrap();

        let attributes_2: G2Vector = (0..max_attributes - 1)
            .map(|_| G2::random())
            .collect::<Vec<G2>>()
            .into();
        let cred_link_2 = l_1_issuer
            .delegate(
                attributes_2.clone(),
                l_2_issuer_vk.clone(),
                &l_1_issuer_sk,
                &params2,
            )
            .unwrap();
        let mut chain_2 = chain_1.clone();
        chain_2.extend_with_even(cred_link_2).unwrap();

        let com_2 = AttributeToken::comm_phase(
            &chain_2,
            vec![HashSet::<usize>::new(); 2],
            &params1,
            &params2,
        )
        .unwrap();
        let c_2 = FieldElement::random();
        let resp_2 = AttributeToken::resp_phase(
            &chain_2,
            com_2,
            &l_2_issuer_sk.0,
            &c_2,
            vec![&l_2_issuer_vk],
            vec![&l_1_issuer_vk],
            &params1,
            &params2,
        )
        .unwrap();

        let attributes_3: G1Vector = (0..max_attributes - 1)
            .map(|_| G1::random())
            .collect::<Vec<G1>>()
            .into();
        let cred_link_3 = l_2_issuer
            .delegate(
                attributes_3.clone(),
                l_3_issuer_vk.clone(),
                &l_2_issuer_sk,
                &params1,
            )
            .unwrap();
        let mut chain_3 = chain_2.clone();
        chain_3.extend_with_odd(cred_link_3).unwrap();

        let com_3 = AttributeToken::comm_phase(
            &chain_3,
            vec![HashSet::<usize>::new(); 3],
            &params1,
            &params2,
        )
        .unwrap();
        let c_3 = FieldElement::random();
        let resp_3 = AttributeToken::resp_phase(
            &chain_3,
            com_3,
            &l_3_issuer_sk.0,
            &c_3,
            vec![&l_2_issuer_vk],
            vec![&l_1_issuer_vk, &l_3_issuer_vk],
            &params1,
            &params2,
        )
        .unwrap();

        let attributes_4: G2Vector = (0..max_attributes - 1)
            .map(|_| G2::random())
            .collect::<Vec<G2>>()
            .into();
        let cred_link_4 = l_3_issuer
            .delegate(
                attributes_4.clone(),
                l_4_issuer_vk.clone(),
                &l_3_issuer_sk,
                &params2,
            )
            .unwrap();
        let mut chain_4 = chain_3.clone();
        chain_4.extend_with_even(cred_link_4).unwrap();

        let com_4 = AttributeToken::comm_phase(
            &chain_4,
            vec![HashSet::<usize>::new(); 4],
            &params1,
            &params2,
        )
        .unwrap();
        let c_4 = FieldElement::random();
        let resp_4 = AttributeToken::resp_phase(
            &chain_4,
            com_4,
            &l_4_issuer_sk.0,
            &c_4,
            vec![&l_2_issuer_vk, &l_4_issuer_vk],
            vec![&l_1_issuer_vk, &l_3_issuer_vk],
            &params1,
            &params2,
        )
        .unwrap();
    }
}
