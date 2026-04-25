// SPDX-License-Identifier: MIT OR Apache-2.0
//! Benchmarks for zero-copy parser
//!
//! Demonstrates performance benefits of zero-copy parsing vs traditional approaches.

#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::explicit_iter_loop)]
#![allow(missing_docs)]

use aion_context::parser::{AionParser, FileHeader, HEADER_SIZE};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zerocopy::FromBytes;

/// Create a minimal valid AION file for benchmarking
fn create_test_file(size_kb: usize) -> Vec<u8> {
    let total_size = size_kb * 1024;
    let mut data = vec![0u8; total_size];

    // Valid header
    data[0..4].copy_from_slice(b"AION");
    data[4..6].copy_from_slice(&2u16.to_le_bytes());

    // Set reasonable offsets
    let header_end = HEADER_SIZE as u64;
    data[104..112].copy_from_slice(&header_end.to_le_bytes()); // encrypted_rules_offset
    data[112..120].copy_from_slice(&0u64.to_le_bytes()); // encrypted_rules_length
    data[120..128].copy_from_slice(&header_end.to_le_bytes()); // version_chain_offset
    data[128..136].copy_from_slice(&0u64.to_le_bytes()); // version_chain_count
    data[136..144].copy_from_slice(&header_end.to_le_bytes()); // signatures_offset
    data[144..152].copy_from_slice(&0u64.to_le_bytes()); // signatures_count
    data[152..160].copy_from_slice(&header_end.to_le_bytes()); // audit_trail_offset
    data[160..168].copy_from_slice(&0u64.to_le_bytes()); // audit_trail_count

    let string_table_offset = (total_size - 32) as u64;
    data[168..176].copy_from_slice(&string_table_offset.to_le_bytes()); // string_table_offset
    data[176..184].copy_from_slice(&0u64.to_le_bytes()); // string_table_length

    data
}

/// Benchmark: Zero-copy header parsing
fn bench_zero_copy_header(c: &mut Criterion) {
    let data = create_test_file(1); // 1KB file

    c.bench_function("zero_copy_header_parse", |b| {
        b.iter(|| {
            let parser = AionParser::new(black_box(&data)).unwrap();
            black_box(parser.header());
        });
    });
}

/// Benchmark: Traditional deserialization (simulated with serde_json)
fn bench_traditional_deserialization(c: &mut Criterion) {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct TraditionalHeader {
        magic: Vec<u8>,
        version: u16,
        flags: u16,
        file_id: u64,
        current_version: u64,
        root_hash: Vec<u8>,
        current_hash: Vec<u8>,
        created_at: u64,
        modified_at: u64,
        encrypted_rules_offset: u64,
        encrypted_rules_length: u64,
        version_chain_offset: u64,
        version_chain_count: u64,
        signatures_offset: u64,
        signatures_count: u64,
        audit_trail_offset: u64,
        audit_trail_count: u64,
        string_table_offset: u64,
        string_table_length: u64,
        reserved: Vec<u8>,
    }

    let header = TraditionalHeader {
        magic: b"AION".to_vec(),
        version: 2,
        flags: 0,
        file_id: 0,
        current_version: 0,
        root_hash: vec![0; 32],
        current_hash: vec![0; 32],
        created_at: 0,
        modified_at: 0,
        encrypted_rules_offset: 256,
        encrypted_rules_length: 0,
        version_chain_offset: 256,
        version_chain_count: 0,
        signatures_offset: 256,
        signatures_count: 0,
        audit_trail_offset: 256,
        audit_trail_count: 0,
        string_table_offset: 992,
        string_table_length: 0,
        reserved: vec![0; 72],
    };

    let json = serde_json::to_vec(&header).unwrap();

    c.bench_function("traditional_json_deserialize", |b| {
        b.iter(|| {
            let _header: TraditionalHeader = serde_json::from_slice(black_box(&json)).unwrap();
            black_box(_header);
        });
    });
}

/// Benchmark: Section access for different file sizes
fn bench_section_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("section_access");

    for size_kb in [1, 10, 100, 1000].iter() {
        let data = create_test_file(*size_kb);

        group.bench_with_input(
            BenchmarkId::new("string_table", size_kb),
            size_kb,
            |b, _| {
                b.iter(|| {
                    let parser = AionParser::new(&data).unwrap();
                    black_box(parser.string_table_bytes().unwrap());
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: Multiple section accesses (showing zero-copy benefits)
fn bench_multiple_sections(c: &mut Criterion) {
    let data = create_test_file(100); // 100KB file

    c.bench_function("access_all_sections", |b| {
        b.iter(|| {
            let parser = AionParser::new(black_box(&data)).unwrap();

            // Access multiple sections - all zero-copy
            black_box(parser.header());
            black_box(parser.encrypted_rules_bytes().unwrap());
            black_box(parser.version_chain_bytes().unwrap());
            black_box(parser.signatures_bytes().unwrap());
            black_box(parser.audit_trail_bytes().unwrap());
            black_box(parser.string_table_bytes().unwrap());
        });
    });
}

/// Benchmark: Parser construction overhead
fn bench_parser_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_construction");

    for size_kb in [1, 10, 100, 1000, 10000].iter() {
        let data = create_test_file(*size_kb);

        group.bench_with_input(BenchmarkId::new("construct", size_kb), size_kb, |b, _| {
            b.iter(|| {
                let parser = AionParser::new(black_box(&data)).unwrap();
                black_box(parser);
            });
        });
    }

    group.finish();
}

/// Benchmark: Raw header parsing with zerocopy
fn bench_raw_header_parsing(c: &mut Criterion) {
    let data = create_test_file(1);

    c.bench_function("raw_zerocopy_header", |b| {
        b.iter(|| {
            let header = FileHeader::read_from_prefix(black_box(&data)).unwrap();
            black_box(header);
        });
    });
}

criterion_group!(
    benches,
    bench_zero_copy_header,
    bench_traditional_deserialization,
    bench_section_access,
    bench_multiple_sections,
    bench_parser_construction,
    bench_raw_header_parsing,
);

criterion_main!(benches);
