# AION v2 Performance Guide

**Version**: 1.0  
**Last Updated**: 2024-12-09

## Performance Targets (RFC-0018)

| Operation | Target | Status |
|-----------|--------|--------|
| File creation (1MB rules) | <10ms | ✅ ~224µs |
| Version commit (1MB rules) | <5ms | ✅ ~300µs |
| Signature verification | <1ms | ✅ ~50µs |
| File parsing (100 versions) | <3ms | ✅ ~1ms |
| Batch signature (1000 sigs) | <10ms | ✅ ~5ms (parallel) |

## Optimization Techniques

### 1. Parallel Signature Verification

For files with >10 signatures, verification is parallelized using Rayon:

```rust
// Automatic parallel verification for large batches
let result = verify_signatures_batch(&versions, &signatures)?;
```

**Threshold**: 10 signatures (sequential below, parallel above)

**Speedup**: ~4-8x for 100+ signatures on multi-core systems

### 2. Zero-Copy Parsing

The parser uses `zerocopy` crate for memory-mapped file access:

```rust
let parser = AionParser::new(&file_bytes)?;
let header = parser.header(); // No allocation
```

**Benefits**:
- No deserialization overhead
- Direct memory access to file data
- Constant-time header access

### 3. Memory-Mapped I/O

Large files use `memmap2` for efficient I/O:

```rust
use memmap2::Mmap;
let file = File::open(path)?;
let mmap = unsafe { Mmap::map(&file)? };
```

**Benefits**:
- Kernel-managed paging
- Reduced memory pressure
- Efficient random access

### 4. Pre-allocation

Collections are pre-allocated when size is known:

```rust
let mut versions = Vec::with_capacity(version_count);
```

### 5. Lazy Loading

Version entries and signatures are loaded on-demand:

```rust
// Only loads header initially
let parser = AionParser::new(&bytes)?;

// Loads version entry on access
let entry = parser.get_version_entry(42)?;
```

## Benchmarking

Run benchmarks:

```bash
# All benchmarks
cargo bench

# Specific benchmark
cargo bench signature_verification

# With HTML report
cargo bench -- --save-baseline main
```

### Benchmark Suites

| Suite | File | Description |
|-------|------|-------------|
| Crypto | `benches/crypto_benchmarks.rs` | Ed25519, BLAKE3, ChaCha20 |
| File Ops | `benches/file_operations_benchmarks.rs` | Init, commit, verify |
| Parser | `benches/parser_benchmarks.rs` | Zero-copy parsing |

## Profiling

### CPU Profiling

```bash
# Install flamegraph
cargo install flamegraph

# Generate flamegraph
cargo flamegraph --bench crypto_benchmarks
```

### Memory Profiling

```bash
# Using heaptrack
heaptrack ./target/release/aion verify large_file.aion
```

## Configuration

### Thread Pool

Rayon uses system thread count by default. Override:

```rust
rayon::ThreadPoolBuilder::new()
    .num_threads(4)
    .build_global()
    .unwrap();
```

### Build Optimization

Release profile in `Cargo.toml`:

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
```

## Best Practices

1. **Batch Operations**: Use batch verification for multiple signatures
2. **Pre-allocate**: Use `with_capacity()` for known sizes
3. **Avoid Clones**: Pass references instead of owned data
4. **Profile First**: Measure before optimizing

## Metrics

Collect performance metrics:

```rust
use std::time::Instant;

let start = Instant::now();
verify_file(path)?;
println!("Verification took: {:?}", start.elapsed());
```

---

*See [RFC-0018](../rfcs/RFC-0018-performance.md) for detailed performance specifications.*
