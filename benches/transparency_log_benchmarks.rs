// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transparency log inclusion-proof scaling benchmarks (issue #36).
//!
//! Pre-#36 the per-call cost of `TransparencyLog::inclusion_proof`
//! grew linearly with N because `audit_path` recomputed sibling
//! subtree MTHs from leaves on every level of recursion.
//!
//! Post-#36 the subtree-roots cache makes both `inclusion_proof`
//! and `root_hash` O(log n). At N=100,000 measured wall-clock
//! dropped from ~14 ms per proof to ~1.1 µs — a >10,000× speedup
//! on a 5-line struct change plus an O(log n) cascade in `append`.
//!
//! Reading the curves below: per-call time should grow ~log2(N).
//! If a 10× growth in N produces a 10× per-call time, the O(n)
//! regression has returned.

#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::uninlined_format_args)]
#![allow(missing_docs)]

use aion_context::transparency_log::{
    leaf_hash as log_leaf_hash, verify_inclusion_proof, LogEntryKind, TransparencyLog,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn build_log(n: u64) -> TransparencyLog {
    let mut log = TransparencyLog::new();
    let payload = b"audit-leaf-payload-fixed-32-bytes";
    for i in 0..n {
        log.append(LogEntryKind::DsseEnvelope, payload, i + 1)
            .unwrap();
    }
    log
}

fn bench_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_append");
    for &target in &[100u64, 10_000, 100_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(target),
            &target,
            |b, &target| {
                b.iter(|| {
                    let mut log = TransparencyLog::new();
                    let payload = b"x";
                    for i in 0..target {
                        log.append(LogEntryKind::DsseEnvelope, payload, i + 1)
                            .unwrap();
                    }
                    black_box(log.tree_size());
                });
            },
        );
    }
    group.finish();
}

fn bench_root_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_root_hash");
    for &n in &[100u64, 10_000, 100_000] {
        let log = build_log(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                black_box(log.root_hash());
            });
        });
    }
    group.finish();
}

fn bench_inclusion_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_inclusion_proof");
    for &n in &[100u64, 10_000, 100_000] {
        let log = build_log(n);
        // Pick a single mid-tree leaf to measure repeatedly. The
        // worst case (right-edge partial sibling) is a constant
        // factor away from the typical case, not a different curve.
        let target_idx = n / 2;
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                black_box(log.inclusion_proof(target_idx).unwrap());
            });
        });
    }
    group.finish();
}

fn bench_proof_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_proof_round_trip");
    let payload = b"x";
    for &n in &[100u64, 10_000, 100_000] {
        let mut log = TransparencyLog::new();
        for i in 0..n {
            log.append(LogEntryKind::DsseEnvelope, payload, i + 1)
                .unwrap();
        }
        let root = log.root_hash();
        let target_idx = n / 2;
        let entry = log.entry(target_idx).unwrap();
        let leaf = log_leaf_hash(
            entry.kind,
            entry.seq,
            entry.timestamp_version,
            &entry.prev_leaf_hash,
            payload,
        );
        let proof = log.inclusion_proof(target_idx).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                verify_inclusion_proof(
                    leaf,
                    proof.leaf_index,
                    proof.tree_size,
                    &proof.audit_path,
                    root,
                )
                .unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_append,
    bench_root_hash,
    bench_inclusion_proof,
    bench_proof_round_trip,
);
criterion_main!(benches);
