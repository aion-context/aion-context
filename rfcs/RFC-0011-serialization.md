# RFC 0011: Serialization Format

- **Author:** Format Engineer (10+ years binary format design, Protocol Buffers contributor)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

Specification for deterministic binary serialization of AION v2 data structures. Defines encoding rules that ensure identical byte output for identical logical data, enabling cryptographic signatures over serialized content. Prioritizes performance, compactness, and cross-platform compatibility.

## Motivation

### Problem Statement

AION v2 requires deterministic serialization to support:

1. **Cryptographic Signatures:** Same data must always serialize to identical bytes
2. **Cross-Platform Compatibility:** Files must be readable on any architecture
3. **Performance:** Zero-copy deserialization for memory-mapped files
4. **Version Compatibility:** Forward/backward compatibility for format evolution
5. **Debugging:** Human-readable hex dumps for troubleshooting

### Requirements

**Functional Requirements:**
- Deterministic encoding (same input → same output)
- Little-endian byte order for consistency
- Natural alignment for performance
- Compact representation (minimal overhead)
- Self-describing format sections

**Non-Functional Requirements:**
- Zero-copy deserialization support
- Memory-mapped file compatibility
- Validation during deserialization
- Extensible for future features

## Proposal

### Core Principles

#### 1. Deterministic Encoding

Every data structure has exactly one valid byte representation:

```rust
/// Trait for deterministic serialization
pub trait DeterministicSerialize {
    /// Serialize to bytes in canonical form
    fn serialize(&self) -> Result<Vec<u8>>;
    
    /// Get serialized size without allocating
    fn serialized_size(&self) -> usize;
    
    /// Serialize directly to writer
    fn serialize_into<W: Write>(&self, writer: &mut W) -> Result<()>;
}

/// Trait for deterministic deserialization
pub trait DeterministicDeserialize: Sized {
    /// Deserialize from bytes with validation
    fn deserialize(data: &[u8]) -> Result<Self>;
    
    /// Deserialize from specific offset
    fn deserialize_at(data: &[u8], offset: usize) -> Result<(Self, usize)>;
}
```

#### 2. Type System Encoding

**Primitive Types:**
```rust
// All integers use little-endian encoding
impl DeterministicSerialize for u8 {
    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(vec![*self])
    }
}

impl DeterministicSerialize for u16 {
    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.to_le_bytes().to_vec())
    }
}

impl DeterministicSerialize for u32 {
    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.to_le_bytes().to_vec())
    }
}

impl DeterministicSerialize for u64 {
    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.to_le_bytes().to_vec())
    }
}

// Fixed-size arrays
impl<const N: usize> DeterministicSerialize for [u8; N] {
    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.to_vec())
    }
}

// Variable-length byte arrays (length-prefixed)
impl DeterministicSerialize for Vec<u8> {
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        // Length prefix (u64 little-endian)
        result.extend_from_slice(&(self.len() as u64).to_le_bytes());
        
        // Data
        result.extend_from_slice(self);
        
        Ok(result)
    }
}

// Strings (UTF-8, length-prefixed)
impl DeterministicSerialize for String {
    fn serialize(&self) -> Result<Vec<u8>> {
        let bytes = self.as_bytes();
        let mut result = Vec::new();
        
        // Length prefix
        result.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        
        // UTF-8 bytes
        result.extend_from_slice(bytes);
        
        Ok(result)
    }
}
```

**Optional Types:**
```rust
// Option<T> encoded as presence byte + optional data
impl<T: DeterministicSerialize> DeterministicSerialize for Option<T> {
    fn serialize(&self) -> Result<Vec<u8>> {
        match self {
            None => Ok(vec![0u8]), // 0 = None
            Some(value) => {
                let mut result = vec![1u8]; // 1 = Some
                result.extend(value.serialize()?);
                Ok(result)
            }
        }
    }
}
```

### Data Structure Serialization

#### File Header Serialization

```rust
/// Fixed-size file header (256 bytes)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub magic: [u8; 4],           // "AION"
    pub version: u16,             // Format version
    pub flags: u16,               // Feature flags
    pub file_id: u64,            // Unique file identifier
    pub current_version: u64,     // Current version number
    pub file_size: u64,          // Total file size
    pub rules_offset: u64,       // Offset to rules section
    pub rules_size: u64,         // Size of rules section
    pub versions_offset: u64,    // Offset to versions section
    pub versions_count: u64,     // Number of versions
    pub signatures_offset: u64,  // Offset to signatures section
    pub signatures_count: u64,   // Number of signatures
    pub audit_offset: u64,       // Offset to audit section
    pub audit_count: u64,        // Number of audit entries
    pub root_hash: [u8; 32],     // Blake3 hash of entire file
    pub reserved: [u8; 120],     // Reserved for future use
}

impl DeterministicSerialize for FileHeader {
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(256);
        
        // Magic number
        buffer.extend_from_slice(&self.magic);
        
        // Version and flags
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.extend_from_slice(&self.flags.to_le_bytes());
        
        // File metadata
        buffer.extend_from_slice(&self.file_id.to_le_bytes());
        buffer.extend_from_slice(&self.current_version.to_le_bytes());
        buffer.extend_from_slice(&self.file_size.to_le_bytes());
        
        // Section offsets and sizes
        buffer.extend_from_slice(&self.rules_offset.to_le_bytes());
        buffer.extend_from_slice(&self.rules_size.to_le_bytes());
        buffer.extend_from_slice(&self.versions_offset.to_le_bytes());
        buffer.extend_from_slice(&self.versions_count.to_le_bytes());
        buffer.extend_from_slice(&self.signatures_offset.to_le_bytes());
        buffer.extend_from_slice(&self.signatures_count.to_le_bytes());
        buffer.extend_from_slice(&self.audit_offset.to_le_bytes());
        buffer.extend_from_slice(&self.audit_count.to_le_bytes());
        
        // Root hash
        buffer.extend_from_slice(&self.root_hash);
        
        // Reserved space (must be zeros)
        buffer.extend_from_slice(&self.reserved);
        
        debug_assert_eq!(buffer.len(), 256);
        Ok(buffer)
    }
    
    fn serialized_size(&self) -> usize {
        256 // Fixed size
    }
}
```

#### Version Entry Serialization

```rust
/// Single version in the version chain (152 bytes fixed)
#[derive(Debug, Clone)]
pub struct VersionEntry {
    pub version: u64,             // Version number
    pub parent_hash: [u8; 32],    // Parent version hash (zeros for genesis)
    pub content_hash: [u8; 32],   // Hash of this version's content
    pub author_id: u64,           // Author identifier
    pub timestamp: u64,           // Unix timestamp (milliseconds)
    pub flags: u32,               // Version flags
    pub metadata_size: u32,       // Size of attached metadata
    // Followed by metadata_size bytes of metadata
}

impl DeterministicSerialize for VersionEntry {
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(152 + self.metadata.len());
        
        // Fixed fields
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.extend_from_slice(&self.parent_hash);
        buffer.extend_from_slice(&self.content_hash);
        buffer.extend_from_slice(&self.author_id.to_le_bytes());
        buffer.extend_from_slice(&self.timestamp.to_le_bytes());
        buffer.extend_from_slice(&self.flags.to_le_bytes());
        buffer.extend_from_slice(&(self.metadata.len() as u32).to_le_bytes());
        
        // Variable metadata
        buffer.extend_from_slice(&self.metadata);
        
        Ok(buffer)
    }
    
    fn serialized_size(&self) -> usize {
        152 + self.metadata.len()
    }
}
```

#### Signature Serialization

```rust
/// Cryptographic signature (112 bytes fixed)
#[derive(Debug, Clone)]
pub struct VersionSignature {
    pub version: u64,             // Version this signature applies to
    pub author_id: u64,           // Author who created signature
    pub public_key: [u8; 32],     // Ed25519 public key
    pub signature: [u8; 64],      // Ed25519 signature
    pub signed_at: u64,           // Signature timestamp
}

impl DeterministicSerialize for VersionSignature {
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(112);
        
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.extend_from_slice(&self.author_id.to_le_bytes());
        buffer.extend_from_slice(&self.public_key);
        buffer.extend_from_slice(&self.signature);
        buffer.extend_from_slice(&self.signed_at.to_le_bytes());
        
        debug_assert_eq!(buffer.len(), 112);
        Ok(buffer)
    }
    
    fn serialized_size(&self) -> usize {
        112 // Fixed size
    }
}
```

#### Encrypted Rules Serialization

```rust
/// Encrypted rules section
#[derive(Debug, Clone)]
pub struct EncryptedRules {
    pub nonce: [u8; 12],         // ChaCha20-Poly1305 nonce
    pub ciphertext: Vec<u8>,     // Encrypted JSON/YAML data
    pub auth_tag: [u8; 16],      // Poly1305 authentication tag
}

impl DeterministicSerialize for EncryptedRules {
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(28 + self.ciphertext.len());
        
        // Nonce
        buffer.extend_from_slice(&self.nonce);
        
        // Ciphertext length + data
        buffer.extend_from_slice(&(self.ciphertext.len() as u64).to_le_bytes());
        buffer.extend_from_slice(&self.ciphertext);
        
        // Authentication tag
        buffer.extend_from_slice(&self.auth_tag);
        
        Ok(buffer)
    }
}
```

### Collection Serialization

**Variable-Length Collections:**
```rust
// Vec<T> serialized as count + elements
impl<T: DeterministicSerialize> DeterministicSerialize for Vec<T> {
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        
        // Element count (u64)
        buffer.extend_from_slice(&(self.len() as u64).to_le_bytes());
        
        // Each element
        for item in self {
            buffer.extend(item.serialize()?);
        }
        
        Ok(buffer)
    }
}

// HashMap<K,V> serialized in sorted key order for determinism
impl<K, V> DeterministicSerialize for HashMap<K, V>
where
    K: DeterministicSerialize + Ord + Clone,
    V: DeterministicSerialize,
{
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        
        // Sort keys for deterministic ordering
        let mut keys: Vec<_> = self.keys().cloned().collect();
        keys.sort();
        
        // Entry count
        buffer.extend_from_slice(&(keys.len() as u64).to_le_bytes());
        
        // Key-value pairs in sorted order
        for key in keys {
            let value = &self[&key];
            buffer.extend(key.serialize()?);
            buffer.extend(value.serialize()?);
        }
        
        Ok(buffer)
    }
}
```

### Deserialization Implementation

```rust
/// Safe deserialization with validation
impl DeterministicDeserialize for FileHeader {
    fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 256 {
            return Err(AionError::InvalidFileSize {
                minimum: 256,
                actual: data.len(),
            });
        }
        
        let mut offset = 0;
        
        // Magic number
        let magic = [data[0], data[1], data[2], data[3]];
        if magic != [b'A', b'I', b'O', b'N'] {
            return Err(AionError::InvalidMagicNumber);
        }
        offset += 4;
        
        // Version
        let version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        if version > MAX_SUPPORTED_VERSION {
            return Err(AionError::UnsupportedVersion { version });
        }
        offset += 2;
        
        let flags = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        // Continue deserializing remaining fields...
        let file_id = u64::from_le_bytes(
            data[offset..offset + 8].try_into().unwrap()
        );
        offset += 8;
        
        // ... (complete implementation)
        
        Ok(FileHeader {
            magic,
            version,
            flags,
            file_id,
            // ... other fields
        })
    }
}

/// Zero-copy deserialization helper
pub struct FileReader<'a> {
    data: &'a [u8],
}

impl<'a> FileReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() < 256 {
            return Err(AionError::FileTooSmall);
        }
        Ok(Self { data })
    }
    
    /// Get header without copying
    pub fn header(&self) -> Result<FileHeader> {
        FileHeader::deserialize(&self.data[0..256])
    }
    
    /// Get version slice without copying
    pub fn versions(&self) -> Result<&'a [u8]> {
        let header = self.header()?;
        let start = header.versions_offset as usize;
        let size = header.versions_count as usize * 152; // Fixed version size
        
        if start + size > self.data.len() {
            return Err(AionError::InvalidSectionBounds);
        }
        
        Ok(&self.data[start..start + size])
    }
    
    /// Iterator over versions without full deserialization
    pub fn version_iter(&self) -> Result<VersionIterator<'a>> {
        Ok(VersionIterator {
            data: self.versions()?,
            offset: 0,
        })
    }
}

pub struct VersionIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for VersionIterator<'a> {
    type Item = Result<VersionEntry>;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }
        
        match VersionEntry::deserialize_at(self.data, self.offset) {
            Ok((version, size)) => {
                self.offset += size;
                Some(Ok(version))
            }
            Err(e) => Some(Err(e)),
        }
    }
}
```

### Validation Rules

**Structural Validation:**
```rust
pub fn validate_file_structure(data: &[u8]) -> Result<()> {
    let reader = FileReader::new(data)?;
    let header = reader.header()?;
    
    // Validate section boundaries
    if header.rules_offset as usize + header.rules_size as usize > data.len() {
        return Err(AionError::InvalidSectionBounds);
    }
    
    if header.versions_offset as usize + 
       (header.versions_count as usize * 152) > data.len() {
        return Err(AionError::InvalidSectionBounds);
    }
    
    if header.signatures_offset as usize + 
       (header.signatures_count as usize * 112) > data.len() {
        return Err(AionError::InvalidSectionBounds);
    }
    
    // Validate section ordering (rules < versions < signatures < audit)
    if header.rules_offset >= header.versions_offset ||
       header.versions_offset >= header.signatures_offset ||
       header.signatures_offset >= header.audit_offset {
        return Err(AionError::InvalidSectionOrdering);
    }
    
    // Validate counts match actual data
    let version_count = reader.versions()?.len() / 152;
    if version_count != header.versions_count as usize {
        return Err(AionError::VersionCountMismatch {
            header: header.versions_count,
            actual: version_count,
        });
    }
    
    Ok(())
}
```

### Cross-Platform Compatibility

**Endianness Handling:**
```rust
// Always use little-endian for network byte order
#[cfg(target_endian = "big")]
fn to_platform_bytes(value: u64) -> [u8; 8] {
    value.to_le_bytes() // Force little-endian
}

#[cfg(target_endian = "little")]
fn to_platform_bytes(value: u64) -> [u8; 8] {
    value.to_le_bytes() // Native little-endian
}

// Alignment considerations for different architectures
#[repr(C, align(8))]
pub struct AlignedHeader {
    pub header: FileHeader,
}
```

### Performance Optimizations

**Memory-Mapped File Support:**
```rust
use memmap2::Mmap;

pub struct MmapFileReader {
    mmap: Mmap,
}

impl MmapFileReader {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        
        // Validate file structure before returning
        validate_file_structure(&mmap)?;
        
        Ok(Self { mmap })
    }
    
    /// Zero-copy access to file data
    pub fn as_slice(&self) -> &[u8] {
        &self.mmap
    }
    
    /// Get typed reader over mapped data
    pub fn reader(&self) -> FileReader<'_> {
        FileReader::new(&self.mmap).unwrap() // Pre-validated
    }
}
```

**Batch Operations:**
```rust
impl FileHeader {
    /// Serialize multiple headers efficiently
    pub fn serialize_batch(headers: &[Self]) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(headers.len() * 256);
        
        for header in headers {
            buffer.extend(header.serialize()?);
        }
        
        Ok(buffer)
    }
}

/// SIMD-accelerated validation where available
#[cfg(target_arch = "x86_64")]
fn validate_magic_numbers_simd(data: &[u8]) -> bool {
    use std::arch::x86_64::*;
    
    if data.len() < 16 {
        return false;
    }
    
    unsafe {
        let magic_pattern = _mm_set1_epi32(0x4E4F4941); // "AION" as u32
        let chunk = _mm_loadu_si128(data.as_ptr() as *const __m128i);
        let mask = _mm_cmpeq_epi32(chunk, magic_pattern);
        _mm_movemask_epi8(mask) != 0
    }
}
```

## Testing Strategy

### Determinism Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    
    #[test]
    fn test_serialization_determinism() {
        let header = create_test_header();
        
        let bytes1 = header.serialize().unwrap();
        let bytes2 = header.serialize().unwrap();
        
        assert_eq!(bytes1, bytes2, "Serialization must be deterministic");
    }
    
    proptest! {
        #[test]
        fn prop_roundtrip_consistency(
            file_id in any::<u64>(),
            version in 1u64..1000,
            author_id in any::<u64>(),
        ) {
            let original = VersionEntry {
                version,
                author_id,
                // ... other fields
            };
            
            let serialized = original.serialize()?;
            let deserialized = VersionEntry::deserialize(&serialized)?;
            
            prop_assert_eq!(original, deserialized);
        }
        
        #[test]
        fn prop_serialization_size_bounds(data in prop::collection::vec(any::<u8>(), 0..10000)) {
            let serialized = data.serialize()?;
            
            // Size should be data length + 8-byte length prefix
            prop_assert_eq!(serialized.len(), data.len() + 8);
        }
    }
}
```

### Cross-Platform Tests

```rust
#[cfg(test)]
mod cross_platform_tests {
    use super::*;
    
    #[test]
    fn test_endianness_consistency() {
        let value = 0x1234567890ABCDEFu64;
        let bytes = value.to_le_bytes();
        let restored = u64::from_le_bytes(bytes);
        
        assert_eq!(value, restored);
    }
    
    #[test]
    fn test_reference_serialization() {
        // Known good serialization from reference implementation
        let expected_bytes = include_bytes!("../testdata/reference_header.bin");
        
        let header = create_reference_header();
        let actual_bytes = header.serialize().unwrap();
        
        assert_eq!(actual_bytes, expected_bytes);
    }
}
```

## Security Considerations

### Input Validation

All deserialization must validate:
- Section boundaries don't exceed file size
- Count fields match actual data
- Reserved fields are zero
- Alignment requirements met
- No integer overflow in size calculations

### Denial of Service Prevention

```rust
const MAX_FILE_SIZE: u64 = 1 << 30; // 1 GB
const MAX_VERSION_COUNT: u64 = 1 << 20; // 1M versions
const MAX_METADATA_SIZE: u32 = 1 << 16; // 64 KB

fn validate_limits(header: &FileHeader) -> Result<()> {
    if header.file_size > MAX_FILE_SIZE {
        return Err(AionError::FileSizeExceedsLimit {
            size: header.file_size,
            limit: MAX_FILE_SIZE,
        });
    }
    
    if header.versions_count > MAX_VERSION_COUNT {
        return Err(AionError::VersionCountExceedsLimit {
            count: header.versions_count,
            limit: MAX_VERSION_COUNT,
        });
    }
    
    Ok(())
}
```

## Implementation Plan

### Phase 1: Core Types (Week 1)
- Implement basic serialization traits
- Create primitive type serializers
- Set up test framework

### Phase 2: Data Structures (Week 2)  
- Implement all AION data structure serialization
- Add validation logic
- Create deserialization implementations

### Phase 3: Performance (Week 3)
- Add zero-copy deserialization
- Memory-mapped file support
- SIMD optimizations where applicable

### Phase 4: Testing (Week 4)
- Comprehensive test suite
- Cross-platform validation
- Property-based testing
- Performance benchmarks

## References

- [Protocol Buffers Encoding](https://developers.google.com/protocol-buffers/docs/encoding)
- [MessagePack Format](https://msgpack.org/index.html)
- [Cap'n Proto Serialization](https://capnproto.org/)
- [FlatBuffers Documentation](https://google.github.io/flatbuffers/)
- [CBOR RFC 8949](https://tools.ietf.org/html/rfc8949)

## Appendix

### Wire Format Examples

**File Header (256 bytes):**
```
0000: 41 49 4F 4E 02 00 00 00  AION.... (magic + version)
0008: 39 05 00 00 00 00 00 00  ........ (file_id)
0010: 05 00 00 00 00 00 00 00  ........ (current_version)
...
00F0: 00 00 00 00 00 00 00 00  ........ (reserved)
```

**Version Entry (152+ bytes):**
```
0000: 03 00 00 00 00 00 00 00  ........ (version = 3)
0008: 1A 2B 3C 4D 5E 6F 70 81  .+<M^op. (parent_hash)
...
0048: E7 03 00 00 00 00 00 00  ........ (author_id = 999)
0050: 40 77 1B 45 01 00 00 00  @w.E.... (timestamp)
```

### Alignment Requirements

- All multi-byte integers naturally aligned
- Structures padded to 8-byte boundaries
- Sections aligned to page boundaries (4KB) for mmap