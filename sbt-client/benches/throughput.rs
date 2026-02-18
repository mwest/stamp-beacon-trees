//! Throughput benchmarks for the SBT client

use criterion::{criterion_group, criterion_main, Criterion};
use sbt_client::SbtClient;
use sbt_notary::testutil::TestServer;
use sbt_types::Digest;
use tokio::runtime::Runtime;

fn bench_single_timestamp(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let server = rt.block_on(TestServer::start());
    let url = server.url();

    c.bench_function("single_timestamp", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut client = SbtClient::new(url.clone());
                let digest = Digest::new([42u8; 32]);
                client.timestamp(digest).await.expect("timestamp failed");
            })
        })
    });
}

fn bench_sequential_timestamps(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let server = rt.block_on(TestServer::start());
    let url = server.url();

    let mut group = c.benchmark_group("sequential_timestamps");

    for count in [10, 50, 100] {
        group.bench_function(format!("n={}", count), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let mut client = SbtClient::new(url.clone());
                    for i in 0..count {
                        let mut bytes = [0u8; 32];
                        bytes[0] = (i & 0xFF) as u8;
                        bytes[1] = ((i >> 8) & 0xFF) as u8;
                        let digest = Digest::new(bytes);
                        client.timestamp(digest).await.expect("timestamp failed");
                    }
                })
            })
        });
    }

    group.finish();
}

fn bench_concurrent_timestamps(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let server = rt.block_on(TestServer::start());
    let url = server.url();

    let mut group = c.benchmark_group("concurrent_timestamps");

    for count in [10, 50] {
        group.bench_function(format!("n={}", count), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let mut handles = Vec::new();
                    for i in 0..count {
                        let url = url.clone();
                        handles.push(tokio::spawn(async move {
                            let mut client = SbtClient::new(url);
                            let mut bytes = [0u8; 32];
                            bytes[0] = (i & 0xFF) as u8;
                            bytes[1] = ((i >> 8) & 0xFF) as u8;
                            let digest = Digest::new(bytes);
                            client.timestamp(digest).await.expect("timestamp failed");
                        }));
                    }
                    for handle in handles {
                        handle.await.expect("task panicked");
                    }
                })
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_single_timestamp,
    bench_sequential_timestamps,
    bench_concurrent_timestamps,
);
criterion_main!(benches);
