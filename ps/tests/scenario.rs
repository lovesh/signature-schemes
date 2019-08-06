use amcl_wrapper::field_elem::{FieldElementVector, FieldElement};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use ps::signature::Signature;
use ps::keys::keygen;
use ps::pok::*;
use ps::{SignatureGroup, OtherGroup, OtherGroupVec};
use std::collections::{HashSet, HashMap};

#[test]
fn test_scenario_1() {
    // User request signer to sign 10 messages where signer knows only 8 messages, the rest 2 are given in a form of commitment.
    // Once user gets the signature, it engages in a proof of knowledge of signature with a verifier.
    // The user also reveals to the verifier some of the messages.
    let count_msgs = 10;
    let committed_msgs = 2;
    let (sk, vk) = keygen(count_msgs, "test".as_bytes());
    let msgs = FieldElementVector::random(count_msgs);
    let blinding = FieldElement::random();

    // User commits to some messages
    let mut comm = SignatureGroup::new();
    for i in 0..committed_msgs {
        comm += (&vk.Y[i] * &msgs[i]);
    }
    comm += (&vk.g * &blinding);

    {
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
        let chal = PoKVCSignatureGroup::hash_for_challenge(bases.as_slice(), &comm, &pok.random_commitment);

        let responses = pok.gen_response(&chal);

        // Signer verifies the proof of knowledge.
        assert!(PoKVCSignatureGroup::verify(bases.as_slice(), &comm, &pok.random_commitment, &chal, &responses).unwrap());
    }

    // Get signature, unblind it and then verify.
    let sig_blinded = Signature::new_with_committed_attributes(&comm, &msgs.as_slice()[committed_msgs..count_msgs], &sk, &vk).unwrap();
    let sig_unblinded = sig_blinded.get_unblinded_signature(&blinding);
    assert!(sig_unblinded.verify(msgs.as_slice(), &vk).unwrap());

    // Do a proof of knowledge of the signature and also reveal some of the messages.
    let mut revealed_msg_indices = HashSet::new();
    revealed_msg_indices.insert(4);
    revealed_msg_indices.insert(6);
    revealed_msg_indices.insert(9);

    let mut bases = OtherGroupVec::with_capacity(vk.Y_tilde.len() + 2);
    bases.push(vk.X_tilde.clone());
    bases.push(vk.g_tilde.clone());
    for i in 0..vk.Y_tilde.len() {
        if revealed_msg_indices.contains(&i) {
            continue
        }
        bases.push(vk.Y_tilde[i].clone());
    }

    let pok = PoKOfSignature::init(&sig_unblinded, &vk, msgs.as_slice(), revealed_msg_indices.clone()).unwrap();
    let chal = PoKVCOtherGroup::hash_for_challenge(bases.as_slice(), &pok.J, &pok.pok_vc.random_commitment);

    let responses = pok.gen_response(&chal);

    let mut revealed_msgs = HashMap::new();
    for i in &revealed_msg_indices {
        revealed_msgs.insert(i.clone(), msgs[*i].clone());
    }
    assert!(PoKOfSignature::verify(&vk, revealed_msgs.clone(), &pok.sig, &pok.J, &pok.pok_vc.random_commitment, &chal, &responses).unwrap());
}