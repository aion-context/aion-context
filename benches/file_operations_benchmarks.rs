//! File operation benchmarks for AION v2
//!
//! Performance targets from RFC-0018:
//! - File creation: <10ms for 1MB rules
//! - Version commit: <5ms for 1MB rules
//! - File verification: <3ms for 100-version file

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::uninlined_format_args)]

use aion_context::crypto::SigningKey;
use aion_context::operations::{
    commit_version, init_file, verify_file, CommitOptions, InitOptions,
};
use aion_context::types::AuthorId;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tempfile::TempDir;

// ============================================================================
// Helper Functions
// ============================================================================

fn create_temp_dir() -> TempDir {
    TempDir::new().unwrap()
}

fn create_test_key() -> SigningKey {
    SigningKey::generate()
}

fn create_test_rules(size: usize) -> Vec<u8> {
    vec![0x42u8; size]
}

// ============================================================================
// File Initialization Benchmarks
// ============================================================================

fn bench_init_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("init_file");
    let temp_dir = create_temp_dir();
    let signing_key = create_test_key();

    for size in [1024, 10_240, 102_400, 1_048_576].iter() {
        let rules = create_test_rules(*size);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let file_path = temp_dir.path().join(format!("bench_{}.aion", size));
                let options = InitOptions {
                    author_id: AuthorId::new(1001),
                    signing_key: &signing_key,
                    message: "Benchmark init",
                    timestamp: None,
                };

                let result = init_file(
                    black_box(&file_path),
                    black_box(&rules),
                    black_box(&options),
                )
                .unwrap();

                black_box(result);
                // Clean up
                let _ = std::fs::remove_file(&file_path);
            });
        });
    }

    group.finish();
}

// ============================================================================
// Version Commit Benchmarks
// ============================================================================

fn bench_commit_version(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_version");
    let temp_dir = create_temp_dir();
    let signing_key = create_test_key();

    for size in [1024, 10_240, 102_400, 1_048_576].iter() {
        let initial_rules = create_test_rules(1024);
        let new_rules = create_test_rules(*size);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter_batched(
                || {
                    // Setup: create initial file
                    let file_path = temp_dir.path().join(format!("commit_bench_{}.aion", size));
                    let init_options = InitOptions {
                        author_id: AuthorId::new(1002),
                        signing_key: &signing_key,
                        message: "Initial version",
                        timestamp: None,
                    };
                    init_file(&file_path, &initial_rules, &init_options).unwrap();
                    file_path
                },
                |file_path| {
                    // Benchmark: commit new version
                    let commit_options = CommitOptions {
                        author_id: AuthorId::new(1002),
                        signing_key: &signing_key,
                        message: "Benchmark commit",
                        timestamp: None,
                    };

                    let result = commit_version(
                        black_box(&file_path),
                        black_box(&new_rules),
                        black_box(&commit_options),
                    )
                    .unwrap();

                    black_box(result);
                    // Clean up
                    let _ = std::fs::remove_file(&file_path);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ============================================================================
// File Verification Benchmarks
// ============================================================================

fn bench_verify_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_file");
    let temp_dir = create_temp_dir();
    let signing_key = create_test_key();

    // Benchmark verification for files with different version counts
    for version_count in [1, 10, 100, 1000].iter() {
        let file_path = temp_dir
            .path()
            .join(format!("verify_bench_{}.aion", version_count));
        let rules = create_test_rules(1024);

        // Create file with multiple versions
        let init_options = InitOptions {
            author_id: AuthorId::new(1003),
            signing_key: &signing_key,
            message: "Version 1",
            timestamp: None,
        };
        init_file(&file_path, &rules, &init_options).unwrap();

        // Add additional versions
        for i in 2..=*version_count {
            let commit_options = CommitOptions {
                author_id: AuthorId::new(1003),
                signing_key: &signing_key,
                message: &format!("Version {}", i),
                timestamp: None,
            };
            commit_version(&file_path, &rules, &commit_options).unwrap();
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(version_count),
            version_count,
            |b, _| {
                b.iter(|| {
                    let result = verify_file(black_box(&file_path)).unwrap();
                    black_box(result);
                });
            },
        );

        // Clean up
        std::fs::remove_file(&file_path).unwrap();
    }

    group.finish();
}

// ============================================================================
// End-to-End Workflow Benchmarks
// ============================================================================

fn bench_full_workflow(c: &mut Criterion) {
    let temp_dir = create_temp_dir();
    let signing_key = create_test_key();
    let rules = create_test_rules(10_240); // 10KB rules

    c.bench_function("full_workflow_init_commit_verify", |b| {
        b.iter(|| {
            let file_path = temp_dir.path().join("workflow_bench.aion");

            // Init
            let init_options = InitOptions {
                author_id: AuthorId::new(1004),
                signing_key: &signing_key,
                message: "Initial",
                timestamp: None,
            };
            init_file(&file_path, &rules, &init_options).unwrap();

            // Commit
            let commit_options = CommitOptions {
                author_id: AuthorId::new(1004),
                signing_key: &signing_key,
                message: "Update",
                timestamp: None,
            };
            commit_version(&file_path, &rules, &commit_options).unwrap();

            // Verify
            let result = verify_file(&file_path).unwrap();
            black_box(result);

            // Clean up
            std::fs::remove_file(&file_path).unwrap();
        });
    });
}

// ============================================================================
// Multiple Commits Benchmark
// ============================================================================

fn bench_sequential_commits(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential_commits");
    let temp_dir = create_temp_dir();
    let signing_key = create_test_key();
    let rules = create_test_rules(1024);

    for commit_count in [5, 10, 20, 50].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(commit_count),
            commit_count,
            |b, _| {
                b.iter_batched(
                    || {
                        // Setup: create initial file
                        let file_path = temp_dir
                            .path()
                            .join(format!("seq_commits_{}.aion", commit_count));
                        let init_options = InitOptions {
                            author_id: AuthorId::new(1005),
                            signing_key: &signing_key,
                            message: "Initial",
                            timestamp: None,
                        };
                        init_file(&file_path, &rules, &init_options).unwrap();
                        file_path
                    },
                    |file_path| {
                        // Benchmark: multiple sequential commits
                        for i in 2..=*commit_count {
                            let commit_options = CommitOptions {
                                author_id: AuthorId::new(1005),
                                signing_key: &signing_key,
                                message: &format!("Commit {}", i),
                                timestamp: None,
                            };
                            commit_version(&file_path, &rules, &commit_options).unwrap();
                        }

                        // Clean up
                        std::fs::remove_file(&file_path).unwrap();
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_init_file,
    bench_commit_version,
    bench_verify_file,
    bench_full_workflow,
    bench_sequential_commits,
);

criterion_main!(benches);
