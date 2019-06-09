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
Signing is an interactive 2-step process.
1. Each signer generates a secret nonce, generates a "public value" from it and shares this "public value" with every other signer.
    ```
    let my_nonce = Nonce::new(None);
        OR
    let rng = EntropyRng::new();
    let my_nonce = Nonce::new(Some(rng));
    ```

2. Once a signer has got all nonces, it creates a signature using its nonce `my_nonce` and all nonces `all_nonces`. It also need every other signer's verkey. 
    ```
    let msg = "Message to sign";
    let b = msg.as_bytes();
    let all_nonces = vec![my_nonce, others_nonce, ....];
    let all_verkeys = vec![my_vk, others_vk, ....];
    let sig = Signature::new(&b, &my_sk, &my_nonce, &my_vk, &all_nonces, &all_verkeys);
    ```
    
### Signature Aggregation and Verification 
#### Signature Aggregation 
```
let keypair1 = Keypair::new(None);
let keypair2 = Keypair::new(None);
let msg = "Small msg";
let b = m.as_bytes();
let nonce1 = Nonce::new(None);
let nonce2 = Nonce::new(None);
let all_nonces = vec![nonce1, nonce2];
let all_verkeys = vec![keypair1.ver_key.clone(), keypair2.ver_key.clone()];

let sig1 = Signature::new(&b, &keypair1.sig_key, &nonce1, &keypair1.ver_key, &all_nonces, &all_verkeys);
let sig2 = Signature::new(&b, &keypair2.sig_key, &nonce2, &keypair2.ver_key, &all_nonces, &all_verkeys);
let signatures = vec![sig1, sig2];
let aggr_sig: AggregatedSignature = AggregatedSignature::new(&signatures);
        OR
let R = Nonce::aggregate(&all_nonces);
let avk = AggregatedVerKey::new(&all_verkeys);
let L = HashedVerKeys::new(&all_verkeys);
let sig1 = Signature::new_using_aggregated_objs(b, &keypair1.sig_key, &nonce1, &keypair1.ver_key, &R, &L, &avk);    
let sig2 = Signature::new_using_aggregated_objs(b, &keypair2.sig_key, &nonce2, &keypair2.ver_key, &R, &L, &avk);
let signatures = vec![sig1, sig2];
let aggr_sig: AggregatedSignature = AggregatedSignature::new(&signatures);    
```

#### Aggregate Signature Verification
```
assert!(aggr_sig.verify(b, &all_nonces, &all_verkeys));
        OR
let R = Nonce::aggregate(&all_nonces);
let avk = AggregatedVerKey::new(&all_verkeys);
assert!(aggr_sig.verify_using_aggregated_objs(b, &R, &avk));
```

#### Serialization and Deserialization
```
let bs: Vec<u8> = vec![1, 5, 190, 200, ......]

let sk = SigKey::from_bytes(&bs);
let sk_bytes = sk.tobytes();

let vk = VerKey::from_bytes(&bs);
let vk_bytes = vk.tobytes();

Similar for AggregatedVerKey