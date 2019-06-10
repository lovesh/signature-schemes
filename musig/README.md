# API

#### Generate keys
```
let keypair = Keypair::new(None);
    OR
let rng = EntropyRng::new();
let keypair = Keypair::new(Some(rng));

let my_sk = keypair.sig_key;
let my_vk = keypair.ver_key;
```

#### Sign
Signing is an interactive 3-phase process.
1. Each signer generates a secret nonce, commits to that nonce and creates a hash of this commitment. In the first phase, signer generates these and shares the hash with other cosigners..
    ```rust
    let signer = Signer::new(num_cosigners);     // num_cosigners is the total number of signers including the current signer
    signer.init_phase_1();
    ```
    Each signer gives a numeric reference starting from 1 to other signers. These references are local to the signer.  
    On receiving hash `h` from signer referred by `j`, it calls `got_hash`
    ```rust
     signer.got_hash(h, j).unwrap();
    ``` 

2. Once a signer has got hash of commitment from **all** other signers, it shares its commitment with other signers.   
    On receiving commitment `c` from signer referred by `j`, it calls, `got_commitment`. `got_commitment` checks if the hash in phase 1 was for this commitment.   
    Note that `got_commitment` can only be called if it has got hash from all. This can be checked by calling `is_phase_1_complete`  
    ```rust
     signer.got_commitment(c, j).unwrap();
    ```

3.  Once a signer has got commitment from **all** other signers, it generates its signature using `generate_sig`.   
    Note that `generate_sig` can only be called if it has got commitment from all. This can be checked by calling `is_phase_2_complete`
    ```rust
    let msg = "Message to sign";
    let msg_b = msg.as_bytes();
    let all_verkeys = vec![my_vk, others_vk, ....];
    let sig = signer.generate_sig(msg_b, &keypair.sig_key, &keypair.ver_key, &all_verkeys).unwrap();
    ```
    `generate_sig` creates an aggregated verification key and the signer's contribution in the aggregated verification key. Both of them don't depend on the nonce or message but are dependent on the cosigner group. 
    Hence when the same cosigner group is creating many such signatures, it is more efficient to create signatures by computing the aggregate values only once and then reusing them for all subsequent signatures.
    ```rust
    let L = HashedVerKeys::new(&all_verkeys);
    let a = L.hash_with_verkey(&keypair.ver_key);
    let sig = Signer::generate_sig_using_aggregated_objs(msg_b, &keypair.sig_key, &nonce, &keypair.ver_key, &aggregate_nonce, &a, &aggregate_verkey);
    ```
    
### Signature Aggregation and Verification 
#### Signature Aggregation
Once signers have generated their signatures, the can be aggregated together. 
```rust 
let signatures = vec![sig1, sig2];
let aggr_sig = AggregatedSignature::new(&signatures);
```

#### Aggregate Signature Verification
Anyone possessing all the verification keys can verify the aggregate signature using `verify`.
```rust
assert!(aggr_sig.verify(msg_b, &all_verkeys));
```

`verify` will create the aggregated verkey. When many signatures need to be verified using the same cosigner group, it is more efficient to create the aggregated 
verkey once and use that to verify signatures. 
```rust
let avk = AggregatedVerKey::new(&all_verkeys);
assert!(aggr_sig.verify_using_aggregated_verkey(b, &avk));
```

#### Serialization and Deserialization
```
let bs: Vec<u8> = vec![1, 5, 190, 200, ......]

let sk = SigKey::from_bytes(&bs);
let sk_bytes = sk.tobytes();

let vk = VerKey::from_bytes(&bs);
let vk_bytes = vk.tobytes();

Similar for AggregatedVerKey