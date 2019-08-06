// Proof of knowledge of signature, committed values

use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1, G1Vector};
use amcl_wrapper::group_elem_g2::{G2, G2Vector};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use crate::{SignatureGroup, SignatureGroupVec, OtherGroup, OtherGroupVec, ate_2_pairing};
use crate::errors::PSError;

// TODO: Add PoK of committed values while requesting a signature
/*
Proof of knowledge of messages in a vector commitment.
Commit for each message. Receive or generate challenge. Compute response.
*/

macro_rules! impl_PoK_VC {
    ( $PoK_VC:ident, $group_element:ident, $group_element_vec:ident ) => {
        pub struct $PoK_VC<'a> {
            bases: &'a [$group_element],
            exponents: &'a [FieldElement],
            commitment: &'a $group_element,
            blindings: FieldElementVector,
            random_commitment: $group_element
        }

        impl<'a> $PoK_VC<'a> {
            pub fn commit(bases: &'a [$group_element], exponents: &'a [FieldElement], commitment: &'a $group_element) -> Result<Self, PSError> {
                if bases.len() != exponents.len() {
                    return Err(PSError::UnequalNoOfBasesExponents { bases: bases.len(),  exponents: exponents.len() });
                }
                let blindings = FieldElementVector::random(bases.len());
                let mut b = $group_element_vec::with_capacity(bases.len());
                for i in 0..bases.len() {
                    b.push(bases[i].clone())
                }

                let random_commitment = b.multi_scalar_mul_const_time(&blindings).unwrap();
                Ok(Self { bases, exponents, commitment, blindings, random_commitment })
            }

            pub fn hash_for_challenge(&self) -> FieldElement {
                let mut bytes = vec![];
                for b in self.bases {
                    bytes.append(&mut b.to_bytes());
                }
                bytes.append(&mut self.commitment.to_bytes());
                bytes.append(&mut self.random_commitment.to_bytes());
                FieldElement::from_msg_hash(&bytes)
            }

            /// For each exponent, generate a response as blinding[i] - challenge*exponents[i]
            pub fn gen_response(&self, challenge: &FieldElement) -> Vec<FieldElement> {
                let mut resp = vec![];
                for i in 0..self.bases.len() {
                    resp.push(&self.blindings[i] - (challenge * &self.exponents[i]));
                }
                resp
            }

            /// Verify that bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
            pub fn verify(bases: & [$group_element], commitment: & $group_element, random_commitment: &$group_element, challenge: &FieldElement, responses: &[FieldElement]) -> Result<bool, PSError> {
                if bases.len() != responses.len() {
                    return Err(PSError::UnequalNoOfBasesExponents { bases: bases.len(),  exponents: responses.len() });
                }
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
                // =>
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge * random_commitment^-1== 1
                let mut points = $group_element_vec::with_capacity(bases.len() + 2);
                let mut scalars = FieldElementVector::with_capacity(bases.len() + 2);
                for i in 0..bases.len() {
                    points.push(bases[i].clone());
                    scalars.push(responses[i].clone());
                }
                points.push(commitment.clone());
                scalars.push(challenge.clone());
                points.push(random_commitment.negation());
                scalars.push(FieldElement::one());
                let pr = points.multi_scalar_mul_var_time(&scalars).unwrap();
                Ok(pr.is_identity())
            }
        }
    }
}

impl_PoK_VC!(PoKVCSignatureGroup, SignatureGroup, SignatureGroupVec);
impl_PoK_VC!(PoKVCOtherGroup, OtherGroup, OtherGroupVec);

// TODO: Add PoK of signature
/*
As section 6.2 describes, for proving knowledge of a signature, the signature sigma is first randomized and also
transformed into a sequential aggregate signature with extra message t for public key g_tilde (and secret key 1).
1. Say the signature sigma is transformed to sigma_prime = (sigma_prime_1, sigma_prime_2) like step 1 in 6.2
1. The prover then sends sigma_prime and the value J = X_tilde * Y_tilde_1^m1 * Y_tilde_2^m2 * ..... * g_tilde^t and the proof J is formed correctly.
The verifier now checks whether e(sigma_prime_1, J) == e(sigma_prime_2, g_tilde)
*/

// TODO: With PoK of signature, reveal some values

/*
In above protocol, construct J to be of the hidden values only, the verifier will then add the revealed values (raised to the respective generators)
to get a final J which will then be used in the pairing check.
*/

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use std::time::{Duration, Instant};

    #[test]
    fn test_PoK_VC() {
        let n = 5;
        macro_rules! test_PoK_VC {
            ( $PoK_VC:ident, $group_element:ident, $group_element_vec:ident ) => {
                let mut bases = $group_element_vec::with_capacity(n);
                let mut exponents = FieldElementVector::with_capacity(n);
                for _ in 0..n {
                    bases.push($group_element::random());
                    exponents.push(FieldElement::random());
                }
                let commitment = bases.multi_scalar_mul_const_time(&exponents).unwrap();
                let pok = $PoK_VC::commit(bases.as_slice(), exponents.as_slice(), &commitment).unwrap();
                let c = pok.hash_for_challenge();
                let responses = pok.gen_response(&c);
                assert!($PoK_VC::verify(bases.as_slice(), &commitment, &pok.random_commitment, &c, &responses).unwrap());

                // Test random element as commitment
                assert!(!$PoK_VC::verify(bases.as_slice(), &$group_element::random(), &pok.random_commitment, &c, &responses).unwrap());
            }
        }

        test_PoK_VC!(PoKVCSignatureGroup, SignatureGroup, SignatureGroupVec);
        test_PoK_VC!(PoKVCOtherGroup, OtherGroup, OtherGroupVec);
    }
}