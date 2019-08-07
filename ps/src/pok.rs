// Proof of knowledge of signature, committed values

use crate::errors::PSError;
use crate::keys::Verkey;
use crate::signature::Signature;
use crate::{ate_2_pairing, OtherGroup, OtherGroupVec, SignatureGroup, SignatureGroupVec};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem_g2::{G2Vector, G2};
use std::collections::{HashMap, HashSet};

// TODO: Refactor: Create state machine like objects.
// `ProverCommitting` will contains vectors of generators and random values.
// `ProverCommitting` has a `commit` method that optionally takes a value as blinding, if not provided, it creates its own.
// `ProverCommitting` has a `finish` method that results in creation of `ProverCommitted` object after consuming `ProverCommitting`
// `ProverCommitted` marks the end of commitment phase and has the final commitment.
// `ProverCommitted` has a method to generate the challenge by hashing all generators and commitment. It is optional
// to use this method as the challenge may come from a super-protocol or from verifier. It takes a vector of bytes that it concatenates with challenge
// `ProverCommitted` has a method to generate responses. It takes the secrets and the challenge to generate responses.
// During response generation `ProverCommitted` is consumed to create `Proof` object containing the commitments and responses.
// `Proof` can then be verified by the verifier.

/*pub struct ProverCommitting<'a, T: GroupElement> {
    gens: Vec<&'a T>,
    blindings: Vec<FieldElement>,
}

pub struct ProverCommitted<'a, T: GroupElement> {
    gens: Vec<&'a T>,
    blindings: Vec<FieldElement>,
    commitment: T
}

impl<'a, T> ProverCommitting<'a, T> where T: GroupElement {
    pub fn new() -> Self {
        Self {
            gens: vec![],
            blindings: vec![],
        }
    }

    pub fn commit(&mut self, gen: &'a T, blinding: Option<FieldElement>) -> usize {
        let blinding = match blinding {
            Some(b) => b,
            None => FieldElement::random()
        };
        let idx = self.gens.len();
        self.gens.push(gen);
        self.blindings.push(blinding);
        idx
    }

    pub fn finish(self) -> ProverCommitted<'a, T> {
        // XXX: Need multi-scalar multiplication to be implemented for GroupElementVector.
        // XXX: Also implement operator overloading for GroupElement.
        unimplemented!()
    }

    pub fn get_index(&self, idx: usize) -> Result<(&'a T, &FieldElement), PSError> {
        if idx >= self.gens.len() {
            return Err(PSError::GeneralError { msg: format!("index {} greater than size {}", idx, self.gens.len()) });
        }
        Ok((self.gens[idx], &self.blindings[idx]))
    }
}*/

macro_rules! impl_PoK_VC_1 {
    ( $prover_committing:ident, $prover_committed:ident, $proof:ident, $group_element:ident, $group_element_vec:ident ) => {

        pub struct $prover_committing {
            gens: $group_element_vec,
            blindings: FieldElementVector,
        }

        pub struct $prover_committed {
            gens: $group_element_vec,
            blindings: FieldElementVector,
            commitment: $group_element,
        }

        pub struct $proof {
            commitment: $group_element,
            responses: FieldElementVector,
        }

        impl $prover_committing {
            pub fn new() -> Self {
                Self {
                    gens: $group_element_vec::new(0),
                    blindings: FieldElementVector::new(0),
                }
            }

            pub fn commit(&mut self, gen: &$group_element, blinding: Option<&FieldElement>) -> usize {
                let blinding = match blinding {
                    Some(b) => b.clone(),
                    None => FieldElement::random(),
                };
                let idx = self.gens.len();
                self.gens.push(gen.clone());
                self.blindings.push(blinding);
                idx
            }

            pub fn finish(self) -> $prover_committed {
                let commitment = self
                    .gens
                    .multi_scalar_mul_const_time(&self.blindings)
                    .unwrap();
                $prover_committed {
                    gens: self.gens,
                    blindings: self.blindings,
                    commitment,
                }
            }

            pub fn get_index(&self, idx: usize) -> Result<(&$group_element, &FieldElement), PSError> {
                if idx >= self.gens.len() {
                    return Err(PSError::GeneralError {
                        msg: format!("index {} greater than size {}", idx, self.gens.len()),
                    });
                }
                Ok((&self.gens[idx], &self.blindings[idx]))
            }
        }

        impl $prover_committed {
            pub fn generate_challenge(&self, mut extra: Vec<u8>) -> FieldElement {
                let mut bytes = vec![];
                for b in self.gens.as_slice() {
                    bytes.append(&mut b.to_bytes());
                }
                bytes.append(&mut self.commitment.to_bytes());
                bytes.append(&mut extra);
                FieldElement::from_msg_hash(&bytes)
            }

            pub fn gen_proof(self, challenge: &FieldElement, secrets: &[FieldElement]) -> Result<$proof, PSError> {
                if secrets.len() != self.gens.len() {
                    return Err(PSError::UnequalNoOfBasesExponents {
                        bases: self.gens.len(),
                        exponents: secrets.len(),
                    });
                }
                let mut responses = FieldElementVector::with_capacity(self.gens.len());
                for i in 0..self.gens.len() {
                    responses.push(&self.blindings[i] - (challenge * &secrets[i]));
                }
                Ok(
                    $proof {
                        commitment: self.commitment,
                        responses,
                    }
                )
            }
        }

        impl $proof {
            pub fn verify(&self, bases: &[$group_element], commitment: &$group_element, challenge: &FieldElement) -> Result<bool, PSError> {
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
                // =>
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge * random_commitment^-1 == 1
                let mut points = $group_element_vec::from(bases);
                let mut scalars = self.responses.clone();
                points.push(commitment.clone());
                scalars.push(challenge.clone());
                let pr = points.multi_scalar_mul_var_time(&scalars).unwrap() - &self.commitment;
                Ok(pr.is_identity())
            }
        }
    }
}

impl_PoK_VC_1!(ProverCommittingSignatureGroup, ProverCommittedSignatureGroup, ProofSignatureGroup, SignatureGroup, SignatureGroupVec);
impl_PoK_VC_1!(ProverCommittingOtherGroup, ProverCommittedOtherGroup, ProofOtherGroup, OtherGroup, OtherGroupVec);

macro_rules! impl_PoK_VC {
    ( $PoK_VC:ident, $group_element:ident, $group_element_vec:ident ) => {
        /// Proof of knowledge of messages in a vector commitment.
        /// Commit for each message. Receive or generate challenge. Compute response.
        pub struct $PoK_VC {
            exponents: FieldElementVector,
            blindings: FieldElementVector,
            pub random_commitment: $group_element,
        }

        impl $PoK_VC {
            /// For each element in `bases`, generate a new random element `r` and compute `bases[i]^r` and add all such products.
            /// Uses multi-exponentiation.
            pub fn commit(
                bases: &[$group_element],
                exponents: &[FieldElement],
            ) -> Result<Self, PSError> {
                if bases.len() != exponents.len() {
                    return Err(PSError::UnequalNoOfBasesExponents {
                        bases: bases.len(),
                        exponents: exponents.len(),
                    });
                }
                let blindings = FieldElementVector::random(bases.len());
                let mut b = $group_element_vec::with_capacity(bases.len());
                for i in 0..bases.len() {
                    b.push(bases[i].clone())
                }

                let random_commitment = b.multi_scalar_mul_const_time(&blindings).unwrap();
                Ok(Self {
                    exponents: FieldElementVector::from(exponents),
                    blindings,
                    random_commitment,
                })
            }

            /// This step will be done by the main protocol for which this PoK is a sub-protocol
            pub fn hash_for_challenge(
                bases: &[$group_element],
                commitment: &$group_element,
                random_commitment: &$group_element,
            ) -> FieldElement {
                let mut bytes = vec![];
                for b in bases {
                    bytes.append(&mut b.to_bytes());
                }
                bytes.append(&mut commitment.to_bytes());
                bytes.append(&mut random_commitment.to_bytes());
                FieldElement::from_msg_hash(&bytes)
            }

            /// For each exponent, generate a response as blinding[i] - challenge*exponents[i]
            pub fn gen_response(&self, challenge: &FieldElement) -> Vec<FieldElement> {
                let mut resp = vec![];
                for i in 0..self.blindings.len() {
                    resp.push(&self.blindings[i] - (challenge * &self.exponents[i]));
                }
                resp
            }

            /// Verify that bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
            pub fn verify(
                bases: &[$group_element],
                commitment: &$group_element,
                random_commitment: &$group_element,
                challenge: &FieldElement,
                responses: &[FieldElement],
            ) -> Result<bool, PSError> {
                if bases.len() != responses.len() {
                    return Err(PSError::UnequalNoOfBasesExponents {
                        bases: bases.len(),
                        exponents: responses.len(),
                    });
                }
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge == random_commitment
                // =>
                // bases[0]^responses[0] * bases[0]^responses[0] * ... bases[i]^responses[i] * commitment^challenge * random_commitment^-1 == 1
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
    };
}

impl_PoK_VC!(PoKVCSignatureGroup, SignatureGroup, SignatureGroupVec);
impl_PoK_VC!(PoKVCOtherGroup, OtherGroup, OtherGroupVec);

/*
As section 6.2 describes, for proving knowledge of a signature, the signature sigma is first randomized and also
transformed into a sequential aggregate signature with extra message t for public key g_tilde (and secret key 1).
1. Say the signature sigma is transformed to sigma_prime = (sigma_prime_1, sigma_prime_2) like step 1 in 6.2
1. The prover then sends sigma_prime and the value J = X_tilde * Y_tilde_1^m1 * Y_tilde_2^m2 * ..... * g_tilde^t and the proof J is formed correctly.
The verifier now checks whether e(sigma_prime_1, J) == e(sigma_prime_2, g_tilde)

To reveal some of the messages from the signature but not all, in above protocol, construct J to be of the hidden values only, the verifier will
then add the revealed values (raised to the respective generators) to get a final J which will then be used in the pairing check.
*/
pub struct PoKOfSignature {
    r: FieldElement,
    t: FieldElement,
    pub sig: Signature,
    pub J: OtherGroup,
    pub pok_vc: PoKVCOtherGroup,
}

impl PoKOfSignature {
    /// Section 6.2 of paper
    pub fn init(
        sig: &Signature,
        vk: &Verkey,
        messages: &[FieldElement],
        revealed_msg_indices: HashSet<usize>,
    ) -> Result<Self, PSError> {
        for idx in &revealed_msg_indices {
            if *idx >= messages.len() {
                return Err(PSError::GeneralError {
                    msg: format!("Index {} should be less than {}", idx, messages.len()),
                });
            }
        }
        Signature::check_verkey_and_messages_compat(messages, vk)?;
        let r = FieldElement::random();
        let t = FieldElement::random();

        // Transform signature to an aggregate signature on (messages, t)
        let sigma_prime_1 = &sig.sigma_1 * &r;
        let sigma_prime_2 = (&sig.sigma_2 + (&sig.sigma_1 * &t)) * &r;

        let mut bases = OtherGroupVec::with_capacity(vk.Y_tilde.len() + 2);
        let mut exponents = FieldElementVector::with_capacity(vk.Y_tilde.len() + 2);
        bases.push(vk.X_tilde.clone());
        exponents.push(FieldElement::one());
        bases.push(vk.g_tilde.clone());
        exponents.push(t.clone());
        for i in 0..vk.Y_tilde.len() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i].clone());
            exponents.push(messages[i].clone());
        }
        let J = bases.multi_scalar_mul_const_time(&exponents).unwrap();
        let pok = PoKVCOtherGroup::commit(bases.as_slice(), exponents.as_slice())?;
        let sigma_prime = Signature {
            sigma_1: sigma_prime_1,
            sigma_2: sigma_prime_2,
        };
        Ok(Self {
            r,
            t,
            sig: sigma_prime,
            J,
            pok_vc: pok,
        })
    }

    pub fn gen_response(&self, challenge: &FieldElement) -> Vec<FieldElement> {
        self.pok_vc.gen_response(challenge)
    }

    pub fn verify(
        vk: &Verkey,
        revealed_msgs: HashMap<usize, FieldElement>,
        sig: &Signature,
        J: &OtherGroup,
        random_commitment: &OtherGroup,
        challenge: &FieldElement,
        responses: &[FieldElement],
    ) -> Result<bool, PSError> {
        vk.validate()?;
        let mut bases = OtherGroupVec::with_capacity(vk.Y_tilde.len() + 2);
        bases.push(vk.X_tilde.clone());
        bases.push(vk.g_tilde.clone());
        for i in 0..vk.Y_tilde.len() {
            if revealed_msgs.contains_key(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i].clone());
        }
        if !PoKVCOtherGroup::verify(
            bases.as_slice(),
            J,
            random_commitment,
            challenge,
            &responses,
        )? {
            return Ok(false);
        }
        // e(sigma_prime_1, J) == e(sigma_prime_2, g_tilde) => e(sigma_prime_1, J) * e(sigma_prime_2, g_tilde^-1) == 1
        let neg_g_tilde = vk.g_tilde.negation();
        let mut j = OtherGroup::new();
        let J = if revealed_msgs.is_empty() {
            J
        } else {
            j = J.clone();
            let mut b = OtherGroupVec::with_capacity(revealed_msgs.len());
            let mut e = FieldElementVector::with_capacity(revealed_msgs.len());
            for (i, m) in revealed_msgs {
                b.push(vk.Y_tilde[i].clone());
                e.push(m.clone());
            }
            j += b.multi_scalar_mul_var_time(&e).unwrap();
            &j
        };
        let res = ate_2_pairing(&sig.sigma_1, J, &sig.sigma_2, &neg_g_tilde);
        Ok(res.is_one())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use crate::keys::keygen;
    use std::time::{Duration, Instant};

    #[test]
    fn test_PoK_VC() {
        // Proof of knowledge of messages and randomness in vector commitment.
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
                let pok = $PoK_VC::commit(bases.as_slice(), exponents.as_slice()).unwrap();
                let c = $PoK_VC::hash_for_challenge(
                    bases.as_slice(),
                    &commitment,
                    &pok.random_commitment,
                );
                let responses = pok.gen_response(&c);
                assert!($PoK_VC::verify(
                    bases.as_slice(),
                    &commitment,
                    &pok.random_commitment,
                    &c,
                    &responses
                )
                .unwrap());

                // Test random element as commitment
                assert!(!$PoK_VC::verify(
                    bases.as_slice(),
                    &$group_element::random(),
                    &pok.random_commitment,
                    &c,
                    &responses
                )
                .unwrap());
            };
        }

        test_PoK_VC!(PoKVCSignatureGroup, SignatureGroup, SignatureGroupVec);
        test_PoK_VC!(PoKVCOtherGroup, OtherGroup, OtherGroupVec);
    }

    #[test]
    fn test_sig_committed_messages() {
        let count_msgs = 5;
        let committed_msgs = 2;
        let (sk, vk) = keygen(count_msgs, "test".as_bytes());
        let msgs = FieldElementVector::random(count_msgs);
        let blinding = FieldElement::random();

        // User commits to messages
        // XXX: In production always use multi-scalar multiplication
        let mut comm = SignatureGroup::new();
        for i in 0..committed_msgs {
            comm += (&vk.Y[i] * &msgs[i]);
        }
        comm += (&vk.g * &blinding);

        // User and signer engage in a proof of knowledge for the above commitment `comm`

        let mut bases = Vec::<SignatureGroup>::new();
        let mut hidden_msgs = Vec::<FieldElement>::new();
        for i in 0..committed_msgs {
            bases.push(vk.Y[i].clone());
            hidden_msgs.push(msgs[i].clone());
        }
        bases.push(vk.g.clone());
        hidden_msgs.push(blinding.clone());

        // User creates a random commitment, computes challenge and response. The proof of knowledge consists of commitment and responses
        let pok = PoKVCSignatureGroup::commit(&bases, &hidden_msgs).unwrap();

        // Note: The challenge may come from the main protocol
        let chal = PoKVCSignatureGroup::hash_for_challenge(
            bases.as_slice(),
            &comm,
            &pok.random_commitment,
        );

        let responses = pok.gen_response(&chal);

        // Signer verifies the proof of knowledge.
        assert!(PoKVCSignatureGroup::verify(
            bases.as_slice(),
            &comm,
            &pok.random_commitment,
            &chal,
            &responses
        )
        .unwrap());

        let sig_blinded = Signature::new_with_committed_attributes(
            &comm,
            &msgs.as_slice()[committed_msgs..count_msgs],
            &sk,
            &vk,
        )
        .unwrap();
        let sig_unblinded = sig_blinded.get_unblinded_signature(&blinding);
        assert!(sig_unblinded.verify(msgs.as_slice(), &vk).unwrap());
    }

    #[test]
    fn test_PoK_sig() {
        let count_msgs = 5;
        let (sk, vk) = keygen(count_msgs, "test".as_bytes());
        let msgs = FieldElementVector::random(count_msgs);
        let sig = Signature::new(msgs.as_slice(), &sk, &vk).unwrap();
        assert!(sig.verify(msgs.as_slice(), &vk).unwrap());

        let mut bases = OtherGroupVec::with_capacity(vk.Y_tilde.len() + 2);
        bases.push(vk.X_tilde.clone());
        bases.push(vk.g_tilde.clone());
        for i in 0..vk.Y_tilde.len() {
            bases.push(vk.Y_tilde[i].clone());
        }

        let pok = PoKOfSignature::init(&sig, &vk, msgs.as_slice(), HashSet::new()).unwrap();
        let chal = PoKVCOtherGroup::hash_for_challenge(
            bases.as_slice(),
            &pok.J,
            &pok.pok_vc.random_commitment,
        );

        let responses = pok.gen_response(&chal);

        assert!(PoKOfSignature::verify(
            &vk,
            HashMap::new(),
            &pok.sig,
            &pok.J,
            &pok.pok_vc.random_commitment,
            &chal,
            &responses
        )
        .unwrap());
    }

    #[test]
    fn test_PoK_sig_reveal_messages() {
        let count_msgs = 10;
        let (sk, vk) = keygen(count_msgs, "test".as_bytes());
        let msgs = FieldElementVector::random(count_msgs);
        let sig = Signature::new(msgs.as_slice(), &sk, &vk).unwrap();
        assert!(sig.verify(msgs.as_slice(), &vk).unwrap());

        let mut revealed_msg_indices = HashSet::new();
        revealed_msg_indices.insert(2);
        revealed_msg_indices.insert(4);
        revealed_msg_indices.insert(9);

        let mut bases = OtherGroupVec::with_capacity(vk.Y_tilde.len() + 2);
        bases.push(vk.X_tilde.clone());
        bases.push(vk.g_tilde.clone());
        for i in 0..vk.Y_tilde.len() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i].clone());
        }

        let pok =
            PoKOfSignature::init(&sig, &vk, msgs.as_slice(), revealed_msg_indices.clone()).unwrap();
        let chal = PoKVCOtherGroup::hash_for_challenge(
            bases.as_slice(),
            &pok.J,
            &pok.pok_vc.random_commitment,
        );

        let responses = pok.gen_response(&chal);

        let mut revealed_msgs = HashMap::new();
        for i in &revealed_msg_indices {
            revealed_msgs.insert(i.clone(), msgs[*i].clone());
        }
        assert!(PoKOfSignature::verify(
            &vk,
            revealed_msgs.clone(),
            &pok.sig,
            &pok.J,
            &pok.pok_vc.random_commitment,
            &chal,
            &responses
        )
        .unwrap());

        // Reveal wrong message
        let mut revealed_msgs_1 = revealed_msgs.clone();
        revealed_msgs_1.insert(2, FieldElement::random());
        assert!(!PoKOfSignature::verify(
            &vk,
            revealed_msgs_1,
            &pok.sig,
            &pok.J,
            &pok.pok_vc.random_commitment,
            &chal,
            &responses
        )
        .unwrap());
    }

    #[test]
    fn test_PoK_VC_1() {
        // Proof of knowledge of messages and randomness in vector commitment.
        let n = 5;
        macro_rules! test_PoK_VC {
            ( $prover_committing:ident, $prover_committed:ident, $proof:ident, $group_element:ident, $group_element_vec:ident ) => {
                let mut gens = $group_element_vec::with_capacity(n);
                let mut secrets = FieldElementVector::with_capacity(n);
                let mut commiting = $prover_committing::new();
                for _ in 0..n - 1 {
                    let g = $group_element::random();
                    commiting.commit(&g, None);
                    gens.push(g);
                    secrets.push(FieldElement::random());
                }

                // Add one of the blindings externally
                let g = $group_element::random();
                let r = FieldElement::random();
                commiting.commit(&g, Some(&r));
                let (g_, r_) = commiting.get_index(n - 1).unwrap();
                assert_eq!(g, *g_);
                assert_eq!(r, *r_);
                gens.push(g);
                secrets.push(FieldElement::random());

                let committed = commiting.finish();
                let commitment = gens.multi_scalar_mul_const_time(&secrets).unwrap();
                let challenge = committed.generate_challenge(commitment.to_bytes());
                let proof = committed.gen_proof(&challenge, secrets.as_slice()).unwrap();

                assert!(proof.verify(gens.as_slice(), &commitment, &challenge).unwrap());
                // Wrong challenge or commitment fails to verify
                assert!(!proof.verify(gens.as_slice(), &$group_element::random(), &challenge).unwrap());
                assert!(!proof.verify(gens.as_slice(), &commitment, &FieldElement::random()).unwrap());
            };
        }

        test_PoK_VC!(ProverCommittingSignatureGroup, ProverCommittedSignatureGroup, ProofSignatureGroup, SignatureGroup, SignatureGroupVec);
        test_PoK_VC!(ProverCommittingOtherGroup, ProverCommittedOtherGroup, ProofOtherGroup, OtherGroup, OtherGroupVec);
    }
}
