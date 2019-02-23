extern crate bls_aggregates;
extern crate criterion;
extern crate hex;

use bls_aggregates::{AggregatePublicKey, AggregateSignature, Keypair, Signature};
use criterion::{black_box, criterion_group, criterion_main, Benchmark, Criterion};

fn compression(c: &mut Criterion) {
    let compressed_g2 = hex::decode("1351bdf582971f796bbaf6320e81251c9d28f674d720cca07ed14596b96697cf18238e0e03ebd7fc1353d885a39407e012cc74bc9f089ed9764bbceac5edba416bef5e73701288977b9cac1ccb6964269d4ebf78b4e8aa7792ba09d3e49c8e6a").unwrap();
    let mut signature = Signature::from_bytes(&compressed_g2).unwrap();

    c.bench(
        "compression",
        Benchmark::new("Decompress a Signature", move |b| {
            b.iter(|| {
                black_box(Signature::from_bytes(&compressed_g2).unwrap());
            })
        })
        .sample_size(100),
    );

    c.bench(
        "compression",
        Benchmark::new("Compress a Signature", move |b| {
            b.iter(|| {
                black_box(Signature::as_bytes(&mut signature));
            })
        })
        .sample_size(10),
    );
}

fn signing(c: &mut Criterion) {
    let keypair = Keypair::random();
    let sk = keypair.sk;
    let pk = keypair.pk;

    let msg = "Some msg";
    let domain = 42;
    let sig = Signature::new(&msg.as_bytes(), domain, &sk);

    c.bench(
        "signing",
        Benchmark::new("Create a Signature", move |b| {
            b.iter(|| {
                black_box(Signature::new(&msg.as_bytes(), domain, &sk));
            })
        })
        .sample_size(10),
    );

    c.bench(
        "signing",
        Benchmark::new("Verify a Signature", move |b| {
            b.iter(|| {
                black_box(sig.verify(&msg.as_bytes(), domain, &pk));
            })
        })
        .sample_size(10),
    );
}

fn aggregation(c: &mut Criterion) {
    let keypair = Keypair::random();
    let sk = keypair.sk;
    let pk = keypair.pk;

    let msg = "Some msg";
    let domain = 42;
    let sig = Signature::new(&msg.as_bytes(), domain, &sk);

    let mut aggregate_publickey = AggregatePublicKey::new();
    aggregate_publickey.add(&pk);

    let mut aggregate_signature = AggregateSignature::new();
    aggregate_signature.add(&sig);

    c.bench(
        "aggregation",
        Benchmark::new("Aggregate a PublicKey", move |b| {
            b.iter(|| {
                black_box(aggregate_publickey.add(&pk));
            })
        })
        .sample_size(100),
    );

    c.bench(
        "aggregation",
        Benchmark::new("Aggregate a Signature", move |b| {
            b.iter(|| {
                black_box(aggregate_signature.add(&sig));
            })
        })
        .sample_size(100),
    );
}

fn aggregate_verfication(c: &mut Criterion) {
    let n = 128;

    let mut pubkeys = vec![];
    let mut agg_sig = AggregateSignature::new();
    let msg = b"signed message";
    let domain = 0;

    for _ in 0..n {
        let keypair = Keypair::random();
        let sig = Signature::new(&msg[..], domain, &keypair.sk);
        agg_sig.add(&sig);
        pubkeys.push(keypair.pk);
    }

    assert_eq!(pubkeys.len(), n);

    c.bench(
        "aggregation",
        Benchmark::new("Verifying aggregate of 128 signatures", move |b| {
            b.iter(|| {
                let agg_pub = AggregatePublicKey::from_public_keys(&pubkeys);
                let verified = agg_sig.verify(&msg[..], domain, &agg_pub);
                assert!(verified);
            })
        })
        .sample_size(100),
    );
}

fn aggregate_verfication_multiple_messages(c: &mut Criterion) {
    let n = 128;

    let mut pubkeys = vec![];
    let mut agg_sig = AggregateSignature::new();

    let mut msgs = vec![
        vec![0; 32],
        vec![1; 32],
    ];

    let domain = 0;

    for i in 0..n {
        let keypair = Keypair::random();

        let msg = &msgs[i / (n / msgs.len())];

        let sig = Signature::new(&msg[..], domain, &keypair.sk);
        agg_sig.add(&sig);

        pubkeys.push(keypair.pk);
    }

    let mut agg_msg = vec![];
    agg_msg.append(&mut msgs[0].to_vec());
    agg_msg.append(&mut msgs[1].to_vec());

    assert_eq!(pubkeys.len(), n as usize);
    assert_eq!(agg_msg.len(), 2 * 32);

    c.bench(
        "aggregation",
        Benchmark::new(
            "Verifying aggregate of 128 signatures with two distinct messages",
            move |b| {
                b.iter(|| {
                    let mut agg_pubs = vec![AggregatePublicKey::new(); 2];

                    for i in 0..n {
                        agg_pubs[i / (n / msgs.len())].add(&pubkeys[i]);
                    }

                    let verified = agg_sig.verify_multiple(&agg_msg[..], domain, &agg_pubs);

                    assert!(verified);
                })
            },
        )
        .sample_size(100),
    );
}

criterion_group!(
    benches,
    compression,
    signing,
    aggregation,
    aggregate_verfication,
    aggregate_verfication_multiple_messages
);
criterion_main!(benches);
