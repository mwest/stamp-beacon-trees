//! Basic usage example for Stamp/Beacon Trees timestamping
//!
//! This example demonstrates:
//! - Building a stamp/beacon tree manually
//! - Creating timestamp proofs
//! - Verifying proofs
//!
//! Run with: cargo run --example basic_usage

use sbt_core::{LeafData, NonceGenerator, StampTreeBuilder};
use sbt_types::{Digest, Timestamp};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Stamp/Beacon Trees Example");
    println!("===========================\n");

    // Step 1: Create some data to timestamp
    let data1 = b"Hello, world!";
    let data2 = b"Timestamp this document";
    let data3 = b"Another piece of data";

    println!("Data to timestamp:");
    println!("  1. {:?}", String::from_utf8_lossy(data1));
    println!("  2. {:?}", String::from_utf8_lossy(data2));
    println!("  3. {:?}", String::from_utf8_lossy(data3));
    println!();

    // Step 2: Hash the data
    let digest1 = hash_data(data1);
    let digest2 = hash_data(data2);
    let digest3 = hash_data(data3);

    println!("Digests:");
    println!("  1. {}", digest1);
    println!("  2. {}", digest2);
    println!("  3. {}", digest3);
    println!();

    // Step 3: Generate nonces for each digest
    let mut nonce_gen = NonceGenerator::new();
    let nonce1 = nonce_gen.generate();
    let nonce2 = nonce_gen.generate();
    let nonce3 = nonce_gen.generate();

    // Step 4: Build a stamp tree
    let mut builder = StampTreeBuilder::new();

    // Add leaves with timing deltas
    // Simulating that digest1 arrived 100ms before root time
    // digest2 arrived at root time
    // digest3 arrived 50ms after root time
    builder.add_leaf(LeafData {
        digest: digest1.clone(),
        nonce: nonce1.clone(),
        delta_nanos: -100_000_000, // -100ms
    });

    builder.add_leaf(LeafData {
        digest: digest2.clone(),
        nonce: nonce2.clone(),
        delta_nanos: 0, // exactly at root time
    });

    builder.add_leaf(LeafData {
        digest: digest3.clone(),
        nonce: nonce3.clone(),
        delta_nanos: 50_000_000, // +50ms
    });

    // Build the tree with current timestamp as root
    let root_timestamp = Timestamp::now();
    let tree = builder.build(root_timestamp);

    println!("Stamp Tree Built:");
    println!("  Leaves:         {}", tree.leaf_count());
    println!("  Root Hash:      {}", tree.root_hash());
    println!("  Root Timestamp: {}", tree.root_timestamp());
    println!();

    // Step 5: Generate Merkle paths for each leaf
    println!("Merkle Paths:");
    for i in 0..tree.leaf_count() {
        let path = tree.generate_path(i).unwrap();
        let leaf = tree.get_leaf(i).unwrap();

        println!("  Leaf {} (index {}):", i + 1, path.leaf_index);
        println!("    Digest:      {}", leaf.digest);
        println!("    Delta:       {} ns", leaf.delta_nanos);
        println!("    Leaf Time:   {}", root_timestamp.add_nanos(leaf.delta_nanos));
        println!("    Path Length: {}", path.siblings.len());

        // Verify the path computes to the root
        let leaf_hash = leaf.compute_hash();
        let computed_root = path.compute_root(&leaf_hash);
        assert_eq!(
            computed_root,
            *tree.root_hash(),
            "Path verification failed!"
        );
        println!("    ✓ Path verified");
        println!();
    }

    // Step 6: Demonstrate proof structure
    println!("In a real system:");
    println!("  1. Notary would sign: H(root_hash || timestamp) with HSM");
    println!("  2. Each client receives: (nonce, merkle_path, delta, signature)");
    println!("  3. Client can verify independently using notary's public key");
    println!();

    println!("✓ Example completed successfully!");

    Ok(())
}

fn hash_data(data: &[u8]) -> Digest {
    let hash = blake3::hash(data);
    Digest::new(*hash.as_bytes())
}
