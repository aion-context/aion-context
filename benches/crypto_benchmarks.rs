//! Cryptographic operation benchmarks for AION v2
//!
//! Performance targets from RFC-0018:
//! - Signature verification: <1ms per signature
//! - Ed25519 signing: <0.5ms
//! - BLAKE3 hashing: <1ms for 1MB
//! - ChaCha20-Poly1305 encryption: <2ms for 1MB

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::uninlined_format_args)]

use aion_context::crypto::{decrypt, encrypt, generate_nonce, hash, keyed_hash, SigningKey};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

// ============================================================================
// Ed25519 Signing Benchmarks
// ============================================================================

fn bench_ed25519_key_generation(c: &mut Criterion) {
    c.bench_function("ed25519_key_generation", |b| {
        b.iter(|| {
            let key = SigningKey::generate();
            black_box(key);
        });
    });
}

fn bench_ed25519_signing(c: &mut Criterion) {
    let key = SigningKey::generate();
    let message = b"Test message for signing benchmark";

    c.bench_function("ed25519_sign_small_message", |b| {
        b.iter(|| {
            let signature = key.sign(black_box(message));
            black_box(signature);
        });
    });
}

fn bench_ed25519_signing_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_sign_large");
    let key = SigningKey::generate();

    for size in [1024, 10_240, 102_400, 1_048_576].iter() {
        let message = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let signature = key.sign(black_box(&message));
                black_box(signature);
            });
        });
    }

    group.finish();
}

fn bench_ed25519_verification(c: &mut Criterion) {
    let key = SigningKey::generate();
    let verifying_key = key.verifying_key();
    let message = b"Test message for verification benchmark";
    let signature = key.sign(message);

    c.bench_function("ed25519_verify_small_message", |b| {
        b.iter(|| {
            let _ = verifying_key.verify(black_box(message), black_box(&signature));
        });
    });
}

fn bench_ed25519_verification_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_verify_large");
    let key = SigningKey::generate();
    let verifying_key = key.verifying_key();

    for size in [1024, 10_240, 102_400, 1_048_576].iter() {
        let message = vec![0x42u8; *size];
        let signature = key.sign(&message);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let _ = verifying_key.verify(black_box(&message), black_box(&signature));
            });
        });
    }

    group.finish();
}

// ============================================================================
// BLAKE3 Hashing Benchmarks
// ============================================================================

fn bench_blake3_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hash");

    for size in [32, 1024, 10_240, 102_400, 1_048_576].iter() {
        let data = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let hash_result = hash(black_box(&data));
                black_box(hash_result);
            });
        });
    }

    group.finish();
}

fn bench_blake3_keyed_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_keyed_hash");
    let key = [0u8; 32];

    for size in [32, 1024, 10_240, 102_400, 1_048_576].iter() {
        let data = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let mac = keyed_hash(black_box(&key), black_box(&data));
                black_box(mac);
            });
        });
    }

    group.finish();
}

// ============================================================================
// ChaCha20-Poly1305 Encryption Benchmarks
// ============================================================================

fn bench_chacha20_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20_poly1305_encrypt");
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"additional authenticated data";

    for size in [32, 1024, 10_240, 102_400, 1_048_576].iter() {
        let plaintext = vec![0x42u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let ciphertext = encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&plaintext),
                    black_box(aad),
                )
                .unwrap();
                black_box(ciphertext);
            });
        });
    }

    group.finish();
}

fn bench_chacha20_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20_poly1305_decrypt");
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"additional authenticated data";

    for size in [32, 1024, 10_240, 102_400, 1_048_576].iter() {
        let plaintext = vec![0x42u8; *size];
        let ciphertext = encrypt(&key, &nonce, &plaintext, aad).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let decrypted = decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&ciphertext),
                    black_box(aad),
                )
                .unwrap();
                black_box(decrypted);
            });
        });
    }

    group.finish();
}

fn bench_nonce_generation(c: &mut Criterion) {
    c.bench_function("generate_nonce", |b| {
        b.iter(|| {
            let nonce = generate_nonce();
            black_box(nonce);
        });
    });
}

// ============================================================================
// Batch Operations
// ============================================================================

fn bench_batch_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_signing");
    let key = SigningKey::generate();

    for count in [10, 100, 1000].iter() {
        let messages: Vec<Vec<u8>> = (0..*count)
            .map(|i| format!("Message {}", i).into_bytes())
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, _| {
            b.iter(|| {
                let signatures: Vec<_> = messages
                    .iter()
                    .map(|msg| key.sign(black_box(msg)))
                    .collect();
                black_box(signatures);
            });
        });
    }

    group.finish();
}

fn bench_batch_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_verification");
    let key = SigningKey::generate();
    let verifying_key = key.verifying_key();

    for count in [10, 100, 1000].iter() {
        let messages: Vec<Vec<u8>> = (0..*count)
            .map(|i| format!("Message {}", i).into_bytes())
            .collect();
        let signatures: Vec<_> = messages.iter().map(|msg| key.sign(msg)).collect();

        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, _| {
            b.iter(|| {
                for (msg, sig) in messages.iter().zip(signatures.iter()) {
                    let _ = verifying_key.verify(black_box(msg), black_box(sig));
                }
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    // Ed25519
    bench_ed25519_key_generation,
    bench_ed25519_signing,
    bench_ed25519_signing_large,
    bench_ed25519_verification,
    bench_ed25519_verification_large,
    // BLAKE3
    bench_blake3_hashing,
    bench_blake3_keyed_hash,
    // ChaCha20-Poly1305
    bench_chacha20_encryption,
    bench_chacha20_decryption,
    bench_nonce_generation,
    // Batch operations
    bench_batch_signing,
    bench_batch_verification,
);

criterion_main!(benches);
