# API

#### Generate parameters which will be used by all signers and verifiers in the system. To simulate a random oracle, a publicly known string is hashed to a generate group element
```rust
let params = Params::new("some publicly known string".as_bytes());
```

#### Generate keys
```rust
let keypair = Keypair::new(None, &params);
    OR
let rng = EntropyRng::new();
let keypair = Keypair::new(Some(rng), &params);

let sk = keypair.sig_key;
let vk = keypair.ver_key;
```

#### Sign
```rust
let msg = "Message to sign";
let b = msg.as_bytes();
let sig = Signature::new(&b, &sk);
```

#### Verify
```rust
sig.verify(&b, &vk, &params)
```


### Multi-Signature and Verification (Not vulnerable to rogue public key attack but slow)
#### Multi-Signature 
```rust
let keypair1 = Keypair::new(None);
let keypair2 = Keypair::new(None);
let msg = "Small msg";
let b = m.as_bytes();
let sig1 = Signature::new(&b, &keypair1.sig_key);
let sig2 = Signature::new(&b, &keypair2.sig_key);
let sigs_and_ver_keys: Vec<(&Signature, &VerKey)> = vec![(&sig1, &keypair1.vk), (&sig2, &keypair2.vk)]
let asig = MultiSignature::new(sigs_and_ver_keys);
```

#### Multi-Signature Verification
```rust
let vks = vec![&keypair1.vk, &keypair2.vk]
asig.verify(&b, vks, &params)
        OR
let vks = vec![&keypair1.vk, &keypair2.vk]
let avk = AggregatedVerKey::new(vks);
assert!(asig.verify_using_aggr_vk(&b, &avk, &params));
```

### Multi-Signature and Verification (vulnerable to rogue public key attack but fast)
#### Proof of possession of secret key (signature over verification key)
##### Generate proof
```rust
let keypair = Keypair::new(None);
let sk = keypair.sig_key;
let vk = keypair.ver_key;

let proof = generate_proof_of_possession(&vk, &sk);
```

##### Verify proof
```rust
verify_proof_of_possession(&proof, &vk, &params)
```

#### Multi-Signature 
```rust
let keypair1 = Keypair::new(None);
let keypair2 = Keypair::new(None);
let msg = "Small msg";
let b = m.as_bytes();
let sig1 = Signature::new(&b, &keypair1.sig_key);
let sig2 = Signature::new(&b, &keypair2.sig_key);
let sigs: Vec<&Signature> = vec![&sig1, &sig2]
let asig = MultiSignatureFast::new(sigs);
```

#### Multi-Signature Verification
```rust
let vks = vec![&keypair1.vk, &keypair2.vk]
asig.verify(&b, vks, &params)
        OR
let vks = vec![&keypair1.vk, &keypair2.vk]
let avk = AggregatedVerKeyFast::new(vks);
assert!(asig.verify_using_aggr_vk(&b, &avk, &params));
```

#### Serialization and Deserialization
```rust
let bs: Vec<u8> = vec![1, 5, 190, 200, ......]

let sk = SigKey::from_bytes(&bs);
let sk_bytes = sk.tobytes();

let vk = VerKey::from_bytes(&bs);
let vk_bytes = vk.tobytes();

let sig = Signature::from_bytes(&bs).unwrap();
let sig_bytes = sig.tobytes();
```
Similar for other objects like AggregatedVerKey, MultiSignature, AggregatedVerKeyFast, MultiSignatureFast  
