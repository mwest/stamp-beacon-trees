//! Benchmarks for core SBT operations: tree construction, path generation,
//! signature verification, hash operations, and serialization.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ed25519_dalek::{Signer, SigningKey};
use sbt_core::{verify_proof, LeafData, StampTreeBuilder};
use sbt_types::{
    messages::{build_sign_message, compute_leaf_hash, hash_pair, MerklePath, TimestampProof},
    Digest, Nonce, PublicKey, Signature, Timestamp,
};

fn make_leaf(i: usize) -> LeafData {
    LeafData {
        digest: Digest::new([(i & 0xFF) as u8; 32]),
        nonce: Nonce::new([((i + 50) & 0xFF) as u8; 32]),
        delta_nanos: i as i64 * 1000,
    }
}

fn bench_tree_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_construction");

    for size in [1, 10, 100, 500, 1000, 5000, 10000] {
        group.bench_with_input(BenchmarkId::new("leaves", size), &size, |b, &size| {
            b.iter(|| {
                let mut builder = StampTreeBuilder::new();
                for i in 0..size {
                    builder.add_leaf(make_leaf(i));
                }
                builder.build(Timestamp::new(1000, 0).unwrap())
            });
        });
    }
    group.finish();
}

fn bench_path_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_generation");

    for size in [10, 100, 1000, 10000] {
        let mut builder = StampTreeBuilder::new();
        for i in 0..size {
            builder.add_leaf(make_leaf(i));
        }
        let tree = builder.build(Timestamp::new(1000, 0).unwrap());

        group.bench_with_input(BenchmarkId::new("leaves", size), &size, |b, &size| {
            b.iter(|| tree.generate_path(size / 2).unwrap());
        });
    }
    group.finish();
}

fn bench_signature_verification(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let digest = Digest::new([1u8; 32]);
    let nonce = Nonce::new([2u8; 32]);
    let timestamp = Timestamp::new(1000, 0).unwrap();
    let leaf_hash = compute_leaf_hash(&digest, &nonce);
    let message = build_sign_message(&leaf_hash, &timestamp);
    let signature = signing_key.sign(&message);

    let proof = TimestampProof {
        digest,
        nonce,
        merkle_path: MerklePath {
            leaf_index: 0,
            siblings: vec![],
        },
        delta_nanos: 0,
        root_timestamp: timestamp,
        signature: Signature::new(signature.to_bytes()),
        notary_pubkey: PublicKey::new(*verifying_key.as_bytes()),
    };

    c.bench_function("verify_proof_single_leaf", |b| {
        b.iter(|| verify_proof(&proof).unwrap());
    });
}

fn bench_hash_operations(c: &mut Criterion) {
    let d1 = Digest::new([1u8; 32]);
    let d2 = Digest::new([2u8; 32]);
    let nonce = Nonce::new([3u8; 32]);

    c.bench_function("compute_leaf_hash", |b| {
        b.iter(|| compute_leaf_hash(&d1, &nonce));
    });

    c.bench_function("hash_pair", |b| {
        b.iter(|| hash_pair(&d1, &d2));
    });
}

fn bench_serialization(c: &mut Criterion) {
    let proof = TimestampProof {
        digest: Digest::new([1u8; 32]),
        nonce: Nonce::new([2u8; 32]),
        merkle_path: MerklePath {
            leaf_index: 42,
            siblings: vec![],
        },
        delta_nanos: 500_000,
        root_timestamp: Timestamp::new(1000, 500_000_000).unwrap(),
        signature: Signature::new([0u8; 64]),
        notary_pubkey: PublicKey::new([0u8; 32]),
    };

    let json = serde_json::to_string(&proof).unwrap();

    c.bench_function("proof_serialize_json", |b| {
        b.iter(|| serde_json::to_string(&proof).unwrap());
    });

    c.bench_function("proof_deserialize_json", |b| {
        b.iter(|| serde_json::from_str::<TimestampProof>(&json).unwrap());
    });
}

criterion_group!(
    benches,
    bench_tree_construction,
    bench_path_generation,
    bench_signature_verification,
    bench_hash_operations,
    bench_serialization,
);
criterion_main!(benches);
