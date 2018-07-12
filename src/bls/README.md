# API

#### Generate keys
```
let keypair = Keypair::new(None);
    OR
let rng = EntropyRng::new();
let keypair = Keypair::new(Some(rng));

let sk = keypair.sig_key;
let vk = keypair.ver_key;
```

#### Sign
```
let msg = "Message to sign";
let b = msg.as_bytes();
let sig = Signature::new(&b, &sk);
```

#### Verify
```
sig.verify(&b, &vk)
```

### Signature Aggregation and Verification (Not vulnerable to rogue public key attack)
#### Signature Aggregation 
```
let keypair1 = Keypair::new(None);
let keypair2 = Keypair::new(None);
let msg = "Small msg";
let b = m.as_bytes();
let sig1 = Signature::new(&b, &keypair1.sig_key);
let sig2 = Signature::new(&b, &keypair2.sig_key);
let sigs_and_ver_keys: Vec<(&Signature, &VerKey)> = vec![(&sig1, &keypair1.vk), (&sig2, &keypair2.vk)]
let asig = AggregatedSignature::new(sigs_and_ver_keys);
```

#### Aggregate Signature Verification
```
let vks = vec![&keypair1.vk, &keypair2.vk]
asig.verify(&b, vks)
        OR
let vks = vec![&keypair1.vk, &keypair2.vk]
let avk = AggregatedVerKey::new(vks);
assert!(asig.verify_using_aggr_vk(&b, &avk));
```

### Signature Aggregation and Verification (vulnerable to rogue public key attack)
#### Proof of possession of public key
##### Generate proof
```
let keypair = Keypair::new(None);
let sk = keypair.sig_key;
let vk = keypair.ver_key;

let proof = generate_proof_of_possession(&vk, &sk);
```

##### Verify proof
```
verify_proof_of_possession(&proof, &vk)
```

#### Signature Aggregation 
```
let keypair1 = Keypair::new(None);
let keypair2 = Keypair::new(None);
let msg = "Small msg";
let b = m.as_bytes();
let sig1 = Signature::new(&b, &keypair1.sig_key);
let sig2 = Signature::new(&b, &keypair2.sig_key);
let sigs: Vec<&Signature> = vec![&sig1, &sig2]
let asig = AggregatedSignatureOld::new(sigs);
```

#### Aggregate Signature Verification
```
let vks = vec![&keypair1.vk, &keypair2.vk]
asig.verify(&b, vks)
        OR
let vks = vec![&keypair1.vk, &keypair2.vk]
let avk = AggregatedVerKeyOld::new(vks);
assert!(asig.verify_using_aggr_vk(&b, &avk));
```