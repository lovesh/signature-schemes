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


### Signature Aggregation and Verification (Not vulnerable to rogue public key attack but slow)
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

### Signature Aggregation and Verification (vulnerable to rogue public key attack but fast)
#### Proof of possession of secret key (signature over verification key)
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
let asig = AggregatedSignatureFast::new(sigs);
```

#### Aggregate Signature Verification
```
let vks = vec![&keypair1.vk, &keypair2.vk]
asig.verify(&b, vks)
        OR
let vks = vec![&keypair1.vk, &keypair2.vk]
let avk = AggregatedVerKeyFast::new(vks);
assert!(asig.verify_using_aggr_vk(&b, &avk));
```

#### Serialization and Deserialization
```
let bs: Vec<u8> = vec![1, 5, 190, 200, ......]

let sk = SigKey::from_bytes(&bs);
let sk_bytes = sk.tobytes();

let vk = VerKey::from_bytes(&bs);
let vk_bytes = vk.tobytes();

let sig = Signature::from_bytes(&bs).unwrap();
let sig_bytes = sig.tobytes();

Similar for other objects like AggregatedVerKey, AggregatedSignature, AggregatedVerKeyFast, AggregatedSignatureFast  
```
