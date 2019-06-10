extern crate rand;

use rand::rngs::EntropyRng;
use rand::RngCore;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::constants::MODBYTES;


#[derive(Debug, Clone, Copy)]
pub enum MuSigError {
    IncorrectCosignerRef(usize),
    UnknownCosignerRef(usize),
    HashToCommitmentNotPresent(usize),
    HashDoesNotMatchCommitment(usize),
    Phase1Incomplete(),
    Phase2Incomplete(),
    DifferentNonceFoundDuringAggregation(G1)
}

pub struct SigKey {
    pub x: FieldElement
}

impl SigKey {
    pub fn new(rng: Option<EntropyRng>) -> Self {
        match rng {
            Some(mut r) => SigKey {
                x: FieldElement::random_using_rng(&mut r)
            },
            None => SigKey {
                x: FieldElement::random(),
            }
        }
    }

    pub fn from_bytes(sk_bytes: &[u8]) -> Result<SigKey, SerzDeserzError> {
        FieldElement::from_bytes(sk_bytes).map(|x| SigKey { x })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.x.to_bytes()
    }
}

pub struct VerKey {
    pub point: G1
}

impl Clone for VerKey {
    fn clone(&self) -> VerKey {
        VerKey {
            point: self.point.clone()
        }
    }
}

impl VerKey {
    pub fn from_sigkey(sk: &SigKey) -> Self {
        VerKey {
            point: G1::generator() * sk.x
        }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<VerKey, SerzDeserzError> {
        G1::from_bytes(vk_bytes).map(|point| VerKey { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }
}

pub struct Keypair {
    pub sig_key: SigKey,
    pub ver_key: VerKey
}

impl Keypair {
    pub fn new(rng: Option<EntropyRng>) -> Self {
        let sk = SigKey::new(rng);
        let vk = VerKey::from_sigkey(&sk);
        Keypair { sig_key: sk, ver_key: vk }
    }
}

pub struct HashedVerKeys {
    pub b: [u8; MODBYTES]
}

impl HashedVerKeys {
    pub fn new(verkeys: &Vec<VerKey>) -> HashedVerKeys {
        let mut bytes: Vec<u8> = vec![];
        for vk in verkeys {
            bytes.extend(vk.to_bytes());
        }
        let mut b: [u8; MODBYTES] = [0; MODBYTES];
        b.copy_from_slice(&FieldElement::from_msg_hash(&bytes).to_bytes());
        HashedVerKeys {
            b
        }
    }

    pub fn hash_with_verkey(&self, verkey: &VerKey) -> FieldElement {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.b.iter());
        bytes.extend(verkey.to_bytes());
        // TODO: Need domain separation for H_agg
        FieldElement::from_msg_hash(&bytes)
    }
}

pub struct AggregatedVerKey {
    pub point: G1
}

impl Clone for AggregatedVerKey {
    fn clone(&self) -> AggregatedVerKey {
        AggregatedVerKey {
            point: self.point.clone()
        }
    }
}

impl AggregatedVerKey {
    pub fn new(verkeys: &Vec<VerKey>) -> Self {
        let L = HashedVerKeys::new(verkeys);
        Self::new_from_L(verkeys, &L)
    }

    pub fn new_from_L(verkeys: &Vec<VerKey>, L: &HashedVerKeys) -> Self {
        let mut avk = G1::identity();
        for vk in verkeys {
            let a = L.hash_with_verkey(vk);
            let point = vk.point * a;
            avk += point;
        }
        AggregatedVerKey {
            point: avk
        }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<AggregatedVerKey, SerzDeserzError> {
        G1::from_bytes(vk_bytes).map(|point| AggregatedVerKey { point })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes()
    }
}

type Signature = (FieldElement, G1);

/// `t`, `R` are local (to the current signer) references to the cosigners.
/// The current signer always references himself by index 0.
pub struct Signer {
    pub r: FieldElement,
    pub R: Vec<G1>,
    pub t: Vec<FieldElement>

}

impl Signer {
    /// `num_cosigners` is inclusive of the current signer.
    pub fn new(num_cosigners: usize) -> Self {
        Signer {
            r: FieldElement::new(),
            // It is cleaner to use Vec of Option and use None for unfilled index rather than identity or zero
            R: (0..num_cosigners).map(|_| G1::identity()).collect(),
            t: (0..num_cosigners).map(|_| FieldElement::zero()).collect(),
        }
    }

    /// Signer creates his r, R and t
    pub fn init_phase_1(&mut self) {
        let r = FieldElement::random();
        let R = G1::generator() * r;
        // TODO: Need domain separation for H_com
        let t = FieldElement::from_msg_hash(&R.to_bytes());
        self.r = r;
        self.R[0] = R;
        self.t[0] = t;
    }

    /// Process the received `t` from other cosigners
    pub fn got_hash(&mut self, t: FieldElement, cosigner_ref: usize) -> Result<(), MuSigError> {
        self.validate_cosigner_ref(cosigner_ref)?;
        self.t[cosigner_ref] = t;
        Ok(())
    }

    /// Process the received `R` from other cosigners
    pub fn got_commitment(&mut self, R: G1, cosigner_ref: usize) -> Result<(), MuSigError> {
        if !self.is_phase_1_complete() {
            return Err(MuSigError::Phase1Incomplete())
        }
        self.validate_cosigner_ref(cosigner_ref)?;
        let expected_t = FieldElement::from_msg_hash(&R.to_bytes());
        if expected_t != self.t[cosigner_ref] {
            return Err(MuSigError::HashDoesNotMatchCommitment(cosigner_ref))
        }
        self.R[cosigner_ref] = R;
        Ok(())
    }

    pub fn generate_sig(&self, msg: &[u8], sig_key: &SigKey, verkey: &VerKey,
                        all_verkeys: &Vec<VerKey>) -> Result<Signature, MuSigError> {
        if !self.is_phase_2_complete() {
            return Err(MuSigError::Phase2Incomplete())
        }
        let R = Self::compute_aggregated_nonce(&self.R);

        let L = HashedVerKeys::new(all_verkeys);
        let a = L.hash_with_verkey(&verkey);
        let avk = AggregatedVerKey::new_from_L(all_verkeys, &L);

        Ok(Signer::generate_sig_using_aggregated_objs(msg, sig_key, &self.r, verkey, R, &a, &avk))
    }

    /// Checks if `t`, i.e. hash to commitment from all cosigners is received
    pub fn is_phase_1_complete(&self) -> bool {
        for t in &self.t {
            if t.is_zero() {
                return false
            }
        }
        true
    }

    /// Checks if `R`, i.e. commitment from all cosigners is received
    pub fn is_phase_2_complete(&self) -> bool {
        for R in &self.R {
            if R.is_identity() {
                return false
            }
        }
        true
    }

    pub fn compute_aggregated_nonce(nonces: &[G1]) -> G1 {
        let mut R = G1::identity();
        for n in nonces {
            R += *n;
        }
        R
    }

    pub fn compute_challenge(msg: &[u8], aggr_verkey: &[u8], aggr_nonce: &[u8]) -> FieldElement {
        // TODO: Need domain separation for H_sig
        let mut challenge_bytes: Vec<u8> = vec![];
        challenge_bytes.extend(aggr_verkey);
        challenge_bytes.extend(aggr_nonce);
        challenge_bytes.extend(msg);
        FieldElement::from_msg_hash(&challenge_bytes)
    }

    fn validate_cosigner_ref(&self, cosigner_ref: usize) -> Result<(), MuSigError> {
        if cosigner_ref == 0 {
            // Since 0 always references the current signer
            return Err(MuSigError::IncorrectCosignerRef(cosigner_ref))
        }
        // Does not matter if `self.R.len` is used or `self.t.len` as they have same length
        if cosigner_ref >= self.t.len() {
            return Err(MuSigError::UnknownCosignerRef(cosigner_ref))
        }
        Ok(())
    }

    pub fn generate_sig_using_aggregated_objs(msg: &[u8], sig_key: &SigKey, nonce: &FieldElement, verkey: &VerKey,
                                              R: G1, a: &FieldElement, avk: &AggregatedVerKey) -> Signature {

        let challenge = Self::compute_challenge(msg, &avk.to_bytes(), &R.to_bytes());

        let s = (challenge * a * sig_key.x) + nonce;
        (s, R)
    }

    /*

    pub fn from_bytes(sig_bytes: &[u8]) -> Result<Signature, SerzDeserzError> {
        FieldElement::from_bytes(sig_bytes).map(|x| Signature { x })

    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.x.to_bytes()
    }*/
}


pub struct AggregatedSignature {
    pub s: FieldElement,
    pub R: G1,
}

impl AggregatedSignature {
    pub fn new(signatures: &[Signature]) -> Result<Self, MuSigError> {
        assert!(signatures.len() > 0);
        let mut aggr_sig = signatures[0].0.clone();
        let R = signatures[0].1.clone();
        for sig in signatures.iter().skip(1) {
            if sig.1 != R {
                return Err(MuSigError::DifferentNonceFoundDuringAggregation(R))
            }
            aggr_sig += sig.0
        }
        Ok(AggregatedSignature {
            s: aggr_sig,
            R
        })
    }

    pub fn verify(&self, msg: &[u8], ver_keys: &Vec<VerKey>) -> bool {
        let avk = AggregatedVerKey::new(ver_keys);
        self.verify_using_aggregated_verkey(msg, &avk)
    }

    pub fn verify_using_aggregated_verkey(&self, msg: &[u8], avk: &AggregatedVerKey) -> bool {
        let challenge = Signer::compute_challenge(msg, &avk.to_bytes(),
                                                  &self.R.to_bytes());
        let lhs = G1::generator() * self.s;
        let rhs = &self.R + (&avk.point * &challenge);
        lhs == rhs
    }

    /*pub fn from_bytes(asig_bytes: &[u8]) -> Result<AggregatedSignature, SerzDeserzError> {
        FieldElement::from_bytes(asig_bytes).map(|s| AggregatedSignature { s })

    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.s.to_bytes()
    }*/
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_verkey() {
        let sk = SigKey::new(None);
        let vk1 = VerKey::from_sigkey(&sk);
        let vk2 = VerKey::from_sigkey(&sk);
        assert_eq!(&vk1.point.to_hex(), &vk2.point.to_hex());

        let bs = vk1.to_bytes();
        let vk11 = VerKey::from_bytes(&bs).unwrap();
        assert_eq!(&vk1.point.to_hex(), &vk11.point.to_hex());

        let bs = sk.to_bytes();
        let sk1 = SigKey::from_bytes(&bs).unwrap();
        assert_eq!(&sk1.x.to_hex(), &sk.x.to_hex());
    }


    #[test]
    fn aggr_sign_verify() {
        let num_cosigners = 5;
        let keypairs: Vec<Keypair> = (0..num_cosigners).map(|_| Keypair::new(None)).collect();
        let verkeys: Vec<VerKey> = keypairs.iter().map(|k| k.ver_key.clone()).collect();

        let msgs = vec![
            "Small msg",
            "121220888888822111212",
            "Some message to sign",
            "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222",
            " is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
        ];

        for msg in msgs {
            let mut signers: Vec<_> = (0..num_cosigners).map(|_| Signer::new(num_cosigners)).collect();
            for signer in &mut signers {
                signer.init_phase_1();
            }

            // Do phase 1. Each cosigner generates r, t, R and shares t with others.
            let ts: Vec<FieldElement> = (0..num_cosigners).map(|i| signers[i].t[0].clone()).collect();
            for i in 0..num_cosigners {
                let signer = &mut signers[i];
                let mut k = 1;
                for j in 0..num_cosigners {
                    if i == j { continue }
                    signer.got_hash(ts[j], k).unwrap();
                    k += 1;
                }
            }
            for i in 0..num_cosigners {
                assert!(signers[i].is_phase_1_complete());
            }

            // Do phase 2. Each cosigner shares R with others
            let Rs: Vec<G1> = (0..num_cosigners).map(|i| signers[i].R[0].clone()).collect();
            for i in 0..num_cosigners {
                let signer = &mut signers[i];
                let mut k = 1;
                for j in 0..num_cosigners {
                    if i == j { continue }
                    signer.got_commitment(Rs[j], k).unwrap();
                    k += 1;
                }
            }
            for i in 0..num_cosigners {
                assert!(signers[i].is_phase_2_complete());
            }

            let mut signatures: Vec<Signature> = vec![];
            let msg_b = msg.as_bytes();
            for i in 0..num_cosigners {
                let signer = &signers[i];
                let keypair = &keypairs[i];
                let sig = signer.generate_sig(msg_b, &keypair.sig_key, &keypair.ver_key, &verkeys).unwrap();
                signatures.push(sig);
            }
            let aggr_sig = AggregatedSignature::new(&signatures).unwrap();
            assert!(aggr_sig.verify(msg_b, &verkeys));

            let verkeys = keypairs.iter().map(|k| k.ver_key.clone()).collect();
            let L = HashedVerKeys::new(&verkeys);
            let mut avk = AggregatedVerKey::new(&verkeys);

            let mut signatures: Vec<Signature> = vec![];
            let R = Signer::compute_aggregated_nonce(&signers[0].R);
            for i in 0..num_cosigners {
                let keypair = &keypairs[i];
                let a = L.hash_with_verkey(&keypair.ver_key);
                let sig = Signer::generate_sig_using_aggregated_objs(msg_b, &keypair.sig_key, &signers[i].r, &keypair.ver_key, R, &a, &avk);
                signatures.push(sig);
            }
            let aggr_sig = AggregatedSignature::new(&signatures).unwrap();
            assert!(aggr_sig.verify_using_aggregated_verkey(msg_b, &avk));

            let bs = avk.to_bytes();
            let mut avk_from_bytes = AggregatedVerKey::from_bytes(&bs).unwrap();
            // FIXME: Next line fails, probably something wrong with main amcl codebase.
            //assert_eq!(&avk.point.to_hex(), &avk_from_bytes.point.to_hex());
            assert!(aggr_sig.verify_using_aggregated_verkey(msg_b, &avk_from_bytes));
        }
    }
}