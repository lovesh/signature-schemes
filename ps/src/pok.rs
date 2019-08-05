// Proof of knowledge of signature, committed values

// TODO: Add PoK of committed values while requesting a signature
/*
Proof of knowledge of messages in a vector commitment.
*/

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