extern crate bls_aggregates;
extern crate criterion;
extern crate hex;

use bls_aggregates::{AggregatePublicKey, AggregateSignature, Signature, Keypair};
use criterion::{Benchmark, Criterion, criterion_group, criterion_main};

fn compression(c: &mut Criterion) {
    let compressed_g2 = hex::decode("1351bdf582971f796bbaf6320e81251c9d28f674d720cca07ed14596b96697cf18238e0e03ebd7fc1353d885a39407e012cc74bc9f089ed9764bbceac5edba416bef5e73701288977b9cac1ccb6964269d4ebf78b4e8aa7792ba09d3e49c8e6a").unwrap();
    let mut signature = Signature::from_bytes(&compressed_g2).unwrap();

    c.bench(
        "compression",
        Benchmark::new("Decompress a Signature", move |b| {
            b.iter(|| {
                Signature::from_bytes(&compressed_g2).unwrap();
            })
        })
        .sample_size(100),
    );

    c.bench(
        "compression",
        Benchmark::new("Compress a Signature", move |b| {
            b.iter(|| {
                Signature::as_bytes(&mut signature);
            })
        })
        .sample_size(10),
    );
}

fn signing(c: &mut Criterion) {
    let keypair = Keypair::random();
    let sk = keypair.sk;
    let pk = keypair.pk;

    let mut msg = "Some msg";
    let domain = 42;
    let sig = Signature::new(&msg.as_bytes(), domain, &sk);

    c.bench(
        "signing",
        Benchmark::new("Create a Signature", move |b| {
            b.iter(|| {
                Signature::new(&msg.as_bytes(), domain, &sk);
            })
        })
        .sample_size(10),
    );

    c.bench(
        "signing",
        Benchmark::new("Verify a Signature", move |b| {
            b.iter(|| {
                sig.verify(&msg.as_bytes(), domain, &pk);
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
                aggregate_publickey.add(&pk);
            })
        })
        .sample_size(100),
    );

    c.bench(
        "aggregation",
        Benchmark::new("Aggregate a Signature", move |b| {
            b.iter(|| {
                aggregate_signature.add(&sig);
            })
        })
        .sample_size(100),
    );
}


criterion_group!(benches, compression, signing, aggregation);
criterion_main!(benches);
