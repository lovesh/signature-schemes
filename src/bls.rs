// BLS Signatures.
// From: "Dan Boneh, Manu Drijvers, Gregory Neven. Compact Multi-Signatures for Smaller Blockchains".
// Available from: https://eprint.iacr.org/2018/483.pdf
// This link was helpful too https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html

extern crate amcl;
extern crate rand;

use rand::rngs::EntropyRng;
use amcl_utils::{random_big_number, hash_on_GroupG1, ate_pairing, hash_as_BigNum};
use types::{BigNum, GroupG1, GroupG2};
use constants::{CURVE_ORDER, GeneratorG2, GroupG2_SIZE};


// TODO: Support point compression
// TODO: Create a common trait that has to_bytes and from_bytes that can be used by the following structs
// TODO: Add domain separation, for single sig, aggregation sig

pub struct SigKey {
    pub x: BigNum
}

impl SigKey {
    pub fn new(rng: Option<EntropyRng>) -> Self {
        SigKey {
            x: random_big_number(&CURVE_ORDER, rng),
        }
    }
}

pub struct VerKey {
    pub point: GroupG2
}

impl Clone for VerKey {
    fn clone(&self) -> VerKey {
        let mut temp_v = GroupG2::new();
        temp_v.copy(&self.point);
        VerKey {
            point: temp_v
        }
    }
}

impl VerKey {
    pub fn from_sigkey(sk: &SigKey) -> Self {
        VerKey {
            point: GeneratorG2.mul(&sk.x),
        }
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

pub struct Signature {
    pub point: GroupG1,
}

impl Clone for Signature {
    fn clone(&self) -> Signature {
        let mut temp_s = GroupG1::new();
        temp_s.copy(&self.point);
        Signature {
            point: temp_s
        }
    }
}

impl Signature {
    // Signature = H_0(msg) * sk
    pub fn new(msg: &[u8], sig_key: &SigKey) -> Self {
        let hash_point = hash_on_GroupG1(msg);
        let sig = hash_point.mul(&sig_key.x);
        // This is different from the paper, the other exponentiation happens in aggregation.
        // This avoids the signer to know beforehand of all other participants
        Signature { point: sig }
    }

    pub fn verify(&self, msg: &[u8], ver_key: &VerKey) -> bool {
        // TODO: Check if point exists on curve, maybe use `rhs`
        if self.point.is_infinity() {
            println!("Signature point at infinity");
            return false;
        }
        let msg_hash_point = hash_on_GroupG1(msg);
        let mut lhs = ate_pairing(&GeneratorG2, &self.point);
        let mut rhs = ate_pairing(&ver_key.point, &msg_hash_point);
        /*let mut lhs_bytes: [u8; FP12_SIZE] = [0; FP12_SIZE];
        let mut rhs_bytes: [u8; FP12_SIZE] = [0; FP12_SIZE];
        lhs.tobytes(&mut lhs_bytes);
        rhs.tobytes(&mut rhs_bytes);
        lhs_bytes.to_vec() == rhs_bytes.to_vec()*/
        lhs.equals(&mut rhs)
    }
}

pub struct AggregatedVerKey {
    pub point: GroupG2
}

impl AggregatedVerKey {
    // Hashes a verkey with all other verkeys using a Hash function `H:{0, 1}* -> Z_q`
    // Takes a verkey `vk_i` and all verkeys `vk_1, vk_2,...vk_n` (including `vk_i`) and calculates
    // `H(vk_i||vk_1||vk_2...||vk_i||...vk_n)`
    pub fn hashed_verkey_for_aggregation(ver_key: &VerKey, all_ver_keys: &Vec<&VerKey>) -> BigNum {
        let mut res_vec: Vec<u8> = Vec::new();

        let mut vk_bytes: [u8; GroupG2_SIZE] = [0; GroupG2_SIZE];
        ver_key.clone().point.tobytes(&mut vk_bytes);
        res_vec.extend_from_slice(&vk_bytes);

        for vk in all_ver_keys {
            let mut vk_bytes: [u8; GroupG2_SIZE] = [0; GroupG2_SIZE];
            let mut vk = vk.to_owned();
            vk.clone().point.tobytes(&mut vk_bytes);
            res_vec.extend_from_slice(&vk_bytes);
        }
        hash_as_BigNum(res_vec.as_ref())
    }

    // Calculates the aggregated verkey
    // For each `v_i` of the verkeys `vk_1, vk_2,...vk_n` calculate
    // `a_i = vk_i * hashed_verkey_for_aggregation(vk_i, [vk_1, vk_2,...vk_n])`
    // Add all `a_i`
    pub fn new(ver_keys: Vec<&VerKey>) -> Self {
        let mut vks: Vec<GroupG2> = Vec::new();

        for mut vk in ver_keys.clone() {
            let h = AggregatedVerKey::hashed_verkey_for_aggregation(&mut vk, &ver_keys);
            /*let (mut a, mut b) = (vk.clone().point, h.clone());
            println!("Hashing vk {} with all leads to {}", &a.tostring(), &b.tostring());*/
            vks.push(vk.point.mul(&h));
        }

        let mut avk: GroupG2 = GroupG2::new();
        avk.inf();
        println!("Aggr vk={}", &avk.tostring());
        for vk in vks {
            avk.add(&vk);
            println!("Aggr vk={}", &avk.tostring());
        }
        AggregatedVerKey { point: avk }
    }
}

pub struct AggregatedSignature {
    pub point: GroupG1
}

impl AggregatedSignature {
    // The aggregator needs to know of all the signer before it can generate the aggregate signature.
    // Takes individual signatures from each of the signers and their verkey and aggregates the
    // signatures. For each signature `s_i` from signer with verkey `v_i` calculate
    // `a_si = s_i * hashed_verkey_for_aggregation(vk_i, [vk_1, vk_2,...vk_n])`
    // Add all `a_si`
    pub fn new(sigs_and_ver_keys: Vec<(&Signature, &VerKey)>) -> Self {
        let all_ver_keys: Vec<&VerKey> = sigs_and_ver_keys.iter().map(|(_, vk)| vk.clone()).collect();
        let mut sigs: Vec<GroupG1> = Vec::new();
        for (sig, mut vk) in sigs_and_ver_keys {
            let h = AggregatedVerKey::hashed_verkey_for_aggregation(&mut vk, &all_ver_keys);
            /*let (mut a, mut b) = (vk.clone().point, h.clone());
            println!("Hashing vk {} with all leads to {}", &a.tostring(), &b.tostring());*/
            sigs.push(sig.point.mul(&h));
        }

        let mut asig: GroupG1 = GroupG1::new();
        asig.inf();
        println!("Aggr sig={}", &asig.tostring());
        for s in sigs {
            asig.add(&s);
            println!("Aggr sig={}", &asig.tostring());
        }
        AggregatedSignature {
            point: asig
        }
    }

    pub fn verify(&self, msg: &[u8], ver_keys: Vec<&VerKey>) -> bool {
        let avk = AggregatedVerKey::new(ver_keys);
        self.verify_using_aggr_vk(msg, &avk)
    }

    // For verifying multiple aggregate signatures from the same signers,
    // an aggregated verkey should be created once and then used for each signature verification
    pub fn verify_using_aggr_vk(&self, msg: &[u8], avk: &AggregatedVerKey) -> bool {
        if self.point.is_infinity() {
            println!("Signature point at infinity");
            return false;
        }
        let msg_hash_point = hash_on_GroupG1(msg);
        let mut lhs = ate_pairing(&GeneratorG2, &self.point);
        let mut rhs = ate_pairing(&avk.point, &msg_hash_point);
        lhs.equals(&mut rhs)
    }

    // TODO: Add batch verification
}

#[cfg(test)]
mod tests {
    // TODO: Add tests for failure
    // TODO: Add more test vectors
    use super::*;

    #[test]
    fn gen_verkey() {
        let sk1 = SigKey::new(None);
        let rng = EntropyRng::new();
        let sk2 = SigKey::new(Some(rng));
        for mut sk in vec![sk1, sk2] {
            let mut vk1 = VerKey::from_sigkey(&sk);
            debug!("{}", sk.x.tostring());
            debug!("{}", &vk1.point.tostring());

            let mut vk2 = VerKey::from_sigkey(&sk);
            debug!("{}", &vk2.point.tostring());

            assert_eq!(&vk1.point.tostring(), &vk2.point.tostring());
        }
    }

    #[test]
    fn sign_verify() {
        let keypair = Keypair::new(None);
        let sk = keypair.sig_key;
        let vk = keypair.ver_key;

        let msg = "Small msg";
        let msg1 = "121220888888822111212";
        let msg2 = "Some message to sign";
        let msg3 = "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222";
        for m in vec![msg, msg1, msg2, msg3] {
            let b = m.as_bytes();
            let sig = Signature::new(&b, &sk);
            assert!(sig.verify(&b, &vk));
        }
    }

    #[test]
    fn signature_at_infinity() {
        let keypair = Keypair::new(None);
        let sk = keypair.sig_key;
        let vk = keypair.ver_key;

        let msg = "Small msg".as_bytes();
        let mut sig = Signature { point: GroupG1::new() };
        sig.point.inf();
        assert_eq!(sig.verify(&msg, &vk), false);
    }

    #[test]
    fn aggr_sign_verify() {
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
            let mut sigs_and_ver_keys: Vec<(Signature, VerKey)> = Vec::new();
            let mut vks: Vec<VerKey> = Vec::new();

            for keypair in vec![&keypair1, &keypair2, &keypair3, &keypair4, &keypair5] {
                let sig = Signature::new(&b, &keypair.sig_key);
                assert!(sig.verify(&b, &keypair.ver_key));
                let v = keypair.ver_key.clone();
                vks.push(v);
                let v = keypair.ver_key.clone();
                sigs_and_ver_keys.push((sig, v));
            }

            let vks_1: Vec<&VerKey> = vks.iter().map(|v| v).collect();
            let vks_2: Vec<&VerKey> = vks.iter().map(|v| v).collect();
            let sigs_and_ver_keys: Vec<(&Signature, &VerKey)> = sigs_and_ver_keys.iter().map(|(s, v)| (s, v)).collect();
            let asig = AggregatedSignature::new(sigs_and_ver_keys);
            assert!(asig.verify(&b, vks_1));
            let avk = AggregatedVerKey::new(vks_2);
            assert!(asig.verify_using_aggr_vk(&b, &avk));
        }
    }

    #[test]
    fn aggregate_signature_at_infinity() {
        let keypair1 = Keypair::new(None);
        let keypair2 = Keypair::new(None);
        let msg = "Small msg".as_bytes();

        let mut asig = AggregatedSignature { point: GroupG1::new() };
        asig.point.inf();
        let vks: Vec<&VerKey> = vec![&keypair1.ver_key, &keypair2.ver_key];
        assert_eq!(asig.verify(&msg, vks), false);
    }

    // TODO: New test that has benchmark for using AggregatedVerKey
}
