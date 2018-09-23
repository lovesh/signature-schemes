# BLS12-381 Aggregate Signatures in Rust using Apache Milagro

**WARNING: This is an experiemental library and the cryptography is NOT SAFE!**

Uses the [The Apache Milagro Cryptographic Library](https://github.com/milagro-crypto/amcl).

This crate is heavily based upon work by
[@lovesh](https://github.com/lovesh).

Presently this library only supports features required for Ethereum 2.0
signature validation. The aggregation methods here are vulnerable to the
rouge-key attack.

There has been no public audit or scrutiny placed upon this crate. If you're a
cryptographer I would love to have your input.

## Usage

### Single Signatures

Perform signing and verification of non-aggregate BLS signatures. Supports
serializing and de-serializing both public and secret keys.

```rust
let sk_bytes = vec![
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	78, 252, 122, 126, 32, 0, 75, 89, 252, 31, 42,
	130, 254, 88, 6, 90, 138, 202, 135, 194, 233,
	117, 181, 75, 96, 238, 79, 100, 237, 59, 140, 111
];

// Load some keys from a serialized secret key.
let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
let pk = PublicKey::from_secret_key(&sk);

// Sign a message
let message = "cats".as_bytes();
let signature = Signature::new(&message, &sk);
assert!(signature.verify(&message, &pk));

// Serialize then de-serialize, just 'cause we can.
let pk_bytes = pk.as_bytes();
let pk = PublicKey::from_bytes(&pk_bytes).unwrap();

// Verify the message
assert!(signature.verify(&message, &pk));
```

Generate new "random" secret keys (see SecretKey docs for information on
entropy sources).

```rust
// Generate a random key pair.
let sk = SecretKey::random();
let pk = PublicKey::from_secret_key(&sk);

// Sign and verify a message.
let message = "cats".as_bytes();
let signature = Signature::new(&message, &sk);
assert!(signature.verify(&message, &pk));
```

### Aggregate Signatures

Aggregate signatures and public keys. Supports serializing and de-serializing
both `AggregateSignatures` and `AggregatePublicKeys`.

```rust
let signing_secret_key_bytes = vec![
	vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 98,
	161, 50, 32, 254, 87, 16, 25, 167, 79, 192, 116, 176, 74,
	164, 217, 40, 57, 179, 15, 19, 21, 240, 100, 70, 127, 111,
	170, 129, 137, 42, 53],
	vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53,
	72, 211, 104, 184, 68, 142, 208, 115, 22, 156, 97, 28,
	216, 228, 102, 4, 218, 116, 226, 166, 131, 67, 7, 40, 55,
	157, 167, 157, 127, 143, 13],
];

// Load the key pairs from our serialized secret keys,
let signing_keypairs: Vec<Keypair> = signing_secret_key_bytes
	.iter()
	.map(|bytes| {
		let sk = SecretKey::from_bytes(&bytes).unwrap();
		let pk = PublicKey::from_secret_key(&sk);
		Keypair{ sk, pk }
	}).collect();

let message = "cats".as_bytes();

// Create an aggregate signature over some message, also generating an
// aggregate public key at the same time.
let mut agg_sig = AggregateSignature::new();
let mut agg_pub_key = AggregatePublicKey::new();
for keypair in &signing_keypairs {
	let sig = Signature::new(&message, &keypair.sk);
	agg_sig.add(&sig);
	agg_pub_key.add(&keypair.pk);
}

// Serialize and de-serialize the aggregates, just 'cause we can.
let agg_sig_bytes = agg_sig.as_bytes();
let agg_pub_bytes = agg_pub_key.as_bytes();
let agg_sig = AggregateSignature::
	from_bytes(&agg_sig_bytes).unwrap();
let agg_pub_key = AggregatePublicKey::
	from_bytes(&agg_pub_bytes).unwrap();

/// Verify the AggregateSignature against the AggregatePublicKey
assert!(agg_sig.verify(&message, &agg_pub_key));
```
