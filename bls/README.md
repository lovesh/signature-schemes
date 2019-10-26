# BLS signature

## Overview
The groups for verification key and message and signature are configurable by using feature flag.   
When using feature `SignatureG1`, signature and message are in G1, verification key in G2 which makes signing cheaper but verification expensive.
When using feature `SignatureG2`, signature and message are in G2, verification key in G1 which makes signing expensive but verification cheaper.  
The default feature is `SignatureG2` to keep the verification fast.  
2 variatons of creating multi-sigs are provided, one that requires proof of possesion to avoid rogue key attack and is fast. The other does not 
require proof of possesion but is slower. The former is present in `multi_sig_fast.rs` and latter in `multi_sig_slow.rs`. Both variations differ in 
signature and verkey aggregation only. The signing algorithms for each signer remains same. The verification algorithm remains same as well. 
Threshold signatures can be created but the currently implemented key generation requires a trusted third party but key generation mechanisms without 
needing a trusted third party can be used without changing the signature aggregation or verkey aggregation mechanisms.  

## API
  
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
MultiSignature::verify(&asig, &b, vks, &params)
        OR
let vks = vec![&keypair1.vk, &keypair2.vk]
let avk = AggregatedVerKey::new(vks);
assert!(asig.verify(&b, &avk, &params));
```

### Multi-Signature and Verification (vulnerable to rogue public key attack but fast)
#### Proof of possession of secret key (signature over verification key)
##### Generate proof of possession of signing key
```rust
let keypair = Keypair::new(None);
let sk = keypair.sig_key;
let vk = keypair.ver_key;

let proof = ProofOfPossession::generate(&vk, &sk);
```

##### Verify proof of possession of signing key
```rust
ProofOfPossession::verify(&proof, &vk, &params)
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
MultiSignatureFast::verify(&asig, &b, vks, &params)
        OR
let vks = vec![&keypair1.vk, &keypair2.vk]
let avk = AggregatedVerKeyFast::new(vks);
assert!(asig.verify(&b, &avk, &params));
```

#### Batch Verification of signatures
Use `Signature::batch_verify` and `Signature::batch_verify_distinct_msgs` for batch verification. The former  
does not assume messages are distinct but the latter does. For their speed comparison, run test `batch_verify` 

#### Threshold signature
```rust
// To generate keys using a trusted third party
let threshold = 3;
let total = 5;
let params = Params::new("test".as_bytes());
let (_, signers) = trusted_party_SSS_keygen(threshold, total, &params);

// Once threshold no of signatures are present, use ThresholdScheme::aggregate_sigs
let threshold_sig = ThresholdScheme::aggregate_sigs(threshold, sigs);

// Once threshold no of keys are present, use ThresholdScheme::aggregate_vk
let threshold_vk = ThresholdScheme::aggregate_vk(
            threshold,
            signers
                .iter()
                .map(|s| (s.id, &s.verkey))
                .collect::<Vec<(usize, &VerKey)>>(),
        );

// Now the threshold sig can be verified like a regualar signature
assert!(threshold_sig.verify(&msg, &threshold_vk, &params));
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
