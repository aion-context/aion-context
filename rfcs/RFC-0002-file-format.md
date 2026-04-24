# RFC 0002: Binary File Format Specification

- **Author:** Binary Format Designer (15+ years low-level systems)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

Precise byte-level specification of the AION v2 file format. This is the **implementation blueprint** - every byte position, alignment requirement, and parsing rule is specified. Implementations following this spec will produce bit-identical files.

## Motivation

### Why Binary Format?

**Alternatives Considered:**
- JSON: 3-5x larger, slower parsing, harder to verify integrity
- Protocol Buffers: Requires schema management, harder to inspect
- MessagePack: Non-deterministic encoding, version compatibility issues

**Binary Format Advantages:**
- **Performance:** Zero-copy parsing, memory-mapped I/O
- **Size:** Minimal overhead (<5% vs data)
- **Integrity:** Deterministic encoding enables hash verification
- **Simplicity:** No schema evolution complexity

### Design Goals

1. **Deterministic:** Same data = same bytes (enables signatures)
2. **Aligned:** Natural alignment for zero-copy access
3. **Extensible:** Reserved fields for future features
4. **Inspectable:** Can be parsed with hexdump
5. **Fast:** Random access to sections without full parse

## File Structure Overview

```
┌─────────────────────────────────────────────────────────────┐
│  MAGIC (4 bytes): 0x41 0x49 0x4F 0x4E  ("AION")           │
│  VERSION (2 bytes): 0x0002 (little-endian)                 │
│  ... (rest of 256-byte header)                             │
├─────────────────────────────────────────────────────────────┤
│  ENCRYPTED RULES (variable length)                          │
│  ├─ Nonce (12 bytes)                                       │
│  ├─ Ciphertext (variable)                                  │
│  └─ Auth Tag (16 bytes)                                    │
├─────────────────────────────────────────────────────────────┤
│  VERSION CHAIN (152 bytes per version)                      │
│  ├─ Version 1 Entry                                        │
│  ├─ Version 2 Entry                                        │
│  └─ ...                                                     │
├─────────────────────────────────────────────────────────────┤
│  SIGNATURES (112 bytes per signature)                       │
│  ├─ Signature 1                                            │
│  ├─ Signature 2                                            │
│  └─ ...                                                     │
├─────────────────────────────────────────────────────────────┤
│  AUDIT TRAIL (80 bytes + variable per entry)               │
│  ├─ Audit Entry 1                                          │
│  ├─ Audit Entry 2                                          │
│  └─ ...                                                     │
├─────────────────────────────────────────────────────────────┤
│  STRING TABLE (variable, null-terminated strings)          │
│  ├─ "Genesis version\0"                                    │
│  ├─ "Added fraud detection\0"                              │
│  └─ ...                                                     │
├─────────────────────────────────────────────────────────────┤
│  FILE INTEGRITY HASH (32 bytes, BLAKE3)                    │
└─────────────────────────────────────────────────────────────┘
```

## Detailed Specification

### Header (256 bytes, offset 0x0000)

**All integers are little-endian unless specified.**

```c
struct FileHeader {
    // Bytes 0-3: Magic number (always "AION" = 0x41494F4E)
    uint8_t magic[4];
    
    // Bytes 4-5: Format version (current = 2)
    uint16_t version;
    
    // Bytes 6-7: Feature flags
    // Bit 0: Encrypted (1 = encrypted, 0 = plaintext)
    // Bit 1: Compressed (reserved for future)
    // Bit 2-15: Reserved (must be 0)
    uint16_t flags;
    
    // Bytes 8-15: Unique file identifier
    uint64_t file_id;
    
    // Bytes 16-23: Current version number (monotonically increasing)
    uint64_t current_version;
    
    // Bytes 24-55: Root hash (BLAKE3, genesis version)
    uint8_t root_hash[32];
    
    // Bytes 56-87: Current hash (BLAKE3, latest version)
    uint8_t current_hash[88];
    
    // Bytes 88-95: Creation timestamp (nanoseconds since Unix epoch)
    uint64_t created_at;
    
    // Bytes 96-103: Last modification timestamp
    uint64_t modified_at;
    
    // Bytes 104-111: Encrypted rules section offset
    uint64_t encrypted_rules_offset;
    
    // Bytes 112-119: Encrypted rules section length (bytes)
    uint64_t encrypted_rules_length;
    
    // Bytes 120-127: Version chain section offset
    uint64_t version_chain_offset;
    
    // Bytes 128-135: Version chain count (number of entries)
    uint64_t version_chain_count;
    
    // Bytes 136-143: Signatures section offset
    uint64_t signatures_offset;
    
    // Bytes 144-151: Signatures count
    uint64_t signatures_count;
    
    // Bytes 152-159: Audit trail section offset
    uint64_t audit_trail_offset;
    
    // Bytes 160-167: Audit trail count
    uint64_t audit_trail_count;
    
    // Bytes 168-175: String table offset
    uint64_t string_table_offset;
    
    // Bytes 176-183: String table length
    uint64_t string_table_length;
    
    // Bytes 184-255: Reserved (must be zero)
    uint8_t reserved[72];
};
static_assert(sizeof(FileHeader) == 256);
```

### Encrypted Rules Section

**Offset:** As specified in `header.encrypted_rules_offset`

**Format:** ChaCha20-Poly1305 AEAD encryption

```
┌──────────────────────────────────────┐
│ Nonce (12 bytes)                     │  Random, must be unique per encryption
├──────────────────────────────────────┤
│ Ciphertext (variable length)         │  Encrypted rules data
├──────────────────────────────────────┤
│ Authentication Tag (16 bytes)        │  Poly1305 MAC
└──────────────────────────────────────┘
```

**Additional Authenticated Data (AAD):**
```
aad = file_id (8 bytes) || current_version (8 bytes) || current_hash (32 bytes)
Total: 48 bytes
```

### Version Chain Entry (152 bytes each)

**Offset:** `header.version_chain_offset + (entry_index * 152)`

```c
struct VersionEntry {
    // Bytes 0-7: Version number (1, 2, 3, ...)
    uint64_t version_number;
    
    // Bytes 8-39: Parent hash (BLAKE3 of previous version rules)
    // For version 1 (genesis): all zeros
    uint8_t parent_hash[32];
    
    // Bytes 40-71: Rules hash (BLAKE3 of this version's rules)
    uint8_t rules_hash[32];
    
    // Bytes 72-79: Author ID who created this version
    uint64_t author_id;
    
    // Bytes 80-87: Creation timestamp (nanoseconds since Unix epoch)
    uint64_t timestamp;
    
    // Bytes 88-95: Commit message offset in string table
    uint64_t message_offset;
    
    // Bytes 96-99: Commit message length (bytes)
    uint32_t message_length;
    
    // Bytes 100-151: Reserved (must be zero)
    uint8_t reserved[52];
};
static_assert(sizeof(VersionEntry) == 152);
```

### Signature Entry (112 bytes each)

**Offset:** `header.signatures_offset + (entry_index * 112)`

```c
struct SignatureEntry {
    // Bytes 0-7: Author ID
    uint64_t author_id;
    
    // Bytes 8-39: Ed25519 public key (32 bytes)
    uint8_t public_key[32];
    
    // Bytes 40-103: Ed25519 signature (64 bytes)
    // Signs: BLAKE3(VersionEntry)
    uint8_t signature[64];
    
    // Bytes 104-111: Reserved (must be zero)
    uint8_t reserved[8];
};
static_assert(sizeof(SignatureEntry) == 112);
```

### Audit Trail Entry (80 bytes + variable)

**Offset:** `header.audit_trail_offset + sum(previous_entry_sizes)`

```c
struct AuditEntry {
    // Bytes 0-7: Timestamp (nanoseconds since Unix epoch)
    uint64_t timestamp;
    
    // Bytes 8-15: Author ID who performed action
    uint64_t author_id;
    
    // Bytes 16-17: Action code (enum)
    // 1 = CREATE_GENESIS
    // 2 = COMMIT_VERSION
    // 3 = VERIFY
    // 4 = INSPECT
    // 100+ = Reserved for future
    uint16_t action_code;
    
    // Bytes 18-23: Reserved
    uint8_t reserved1[6];
    
    // Bytes 24-31: Details string offset in string table
    uint64_t details_offset;
    
    // Bytes 32-35: Details string length
    uint32_t details_length;
    
    // Bytes 36-39: Reserved
    uint8_t reserved2[4];
    
    // Bytes 40-71: Previous entry hash (BLAKE3 of previous AuditEntry)
    // For first entry: all zeros
    uint8_t previous_hash[32];
    
    // Bytes 72-79: Reserved
    uint8_t reserved3[8];
};
static_assert(sizeof(AuditEntry) == 80);
```

### String Table

**Offset:** As specified in `header.string_table_offset`

**Format:** Concatenated null-terminated UTF-8 strings

```
"Genesis version\0Added fraud detection\0Updated compliance rules\0"
```

**Rules:**
1. All strings are UTF-8 encoded
2. Each string terminated with single null byte (0x00)
3. No padding between strings
4. Offsets in entries point to first character (not null byte)
5. Lengths in entries do NOT include null terminator

### File Integrity Hash (32 bytes)

**Offset:** End of file minus 32 bytes

**Algorithm:** BLAKE3 of entire file excluding this hash itself

```
hash = BLAKE3(file_bytes[0..file_length-32])
```

## Parsing Algorithm

### Zero-Copy Parsing

```rust
use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref};

pub fn parse_file(data: &[u8]) -> Result<ParsedFile> {
    // 1. Validate minimum size
    if data.len() < 256 + 32 {
        return Err(AionError::FileTooSmall);
    }
    
    // 2. Parse header (zero-copy reference)
    let header = Ref::<_, FileHeader>::new(&data[0..256])
        .ok_or(AionError::InvalidHeader)?
        .into_ref();
    
    // 3. Validate magic
    if &header.magic != b"AION" {
        return Err(AionError::InvalidMagic);
    }
    
    // 4. Check version
    if header.version != 2 {
        return Err(AionError::UnsupportedVersion { 
            version: header.version 
        });
    }
    
    // 5. Parse version chain (zero-copy slice)
    let version_start = header.version_chain_offset as usize;
    let version_count = header.version_chain_count as usize;
    let version_size = version_count * 152;
    let version_data = &data[version_start..version_start + version_size];
    let versions = Ref::<_, [VersionEntry]>::new_slice(version_data)
        .ok_or(AionError::InvalidVersionChain)?
        .into_slice();
    
    // 6. Parse signatures (zero-copy slice)
    let sig_start = header.signatures_offset as usize;
    let sig_count = header.signatures_count as usize;
    let sig_size = sig_count * 112;
    let sig_data = &data[sig_start..sig_start + sig_size];
    let signatures = Ref::<_, [SignatureEntry]>::new_slice(sig_data)
        .ok_or(AionError::InvalidSignatures)?
        .into_slice();
    
    // 7. Verify file integrity hash
    let hash_offset = data.len() - 32;
    let stored_hash = &data[hash_offset..];
    let computed_hash = blake3::hash(&data[..hash_offset]);
    
    if stored_hash != computed_hash.as_bytes() {
        return Err(AionError::CorruptedFile {
            expected: hex::encode(computed_hash),
            actual: hex::encode(stored_hash),
        });
    }
    
    Ok(ParsedFile {
        header,
        versions,
        signatures,
        // ... etc
    })
}
```

## Writing Algorithm

### Deterministic Serialization

```rust
pub fn write_file(file: &File, path: &Path) -> Result<()> {
    let mut buffer = Vec::new();
    
    // 1. Write header (initially with zero offsets)
    let mut header = FileHeader::default();
    header.magic = *b"AION";
    header.version = 2;
    header.file_id = file.id.0;
    header.current_version = file.current_version;
    // ... fill other fields
    
    buffer.extend_from_slice(header.as_bytes());
    assert_eq!(buffer.len(), 256);
    
    // 2. Write encrypted rules
    header.encrypted_rules_offset = buffer.len() as u64;
    buffer.extend_from_slice(&file.encrypted_rules);
    header.encrypted_rules_length = file.encrypted_rules.len() as u64;
    
    // 3. Write version chain
    header.version_chain_offset = buffer.len() as u64;
    header.version_chain_count = file.versions.len() as u64;
    for version in &file.versions {
        buffer.extend_from_slice(version.as_bytes());
    }
    
    // 4. Write signatures
    header.signatures_offset = buffer.len() as u64;
    header.signatures_count = file.signatures.len() as u64;
    for sig in &file.signatures {
        buffer.extend_from_slice(sig.as_bytes());
    }
    
    // 5. Write audit trail
    header.audit_trail_offset = buffer.len() as u64;
    header.audit_trail_count = file.audit_entries.len() as u64;
    for entry in &file.audit_entries {
        buffer.extend_from_slice(entry.as_bytes());
    }
    
    // 6. Write string table
    header.string_table_offset = buffer.len() as u64;
    let string_table = build_string_table(file)?;
    buffer.extend_from_slice(&string_table);
    header.string_table_length = string_table.len() as u64;
    
    // 7. Update header with correct offsets
    buffer[0..256].copy_from_slice(header.as_bytes());
    
    // 8. Compute and append integrity hash
    let hash = blake3::hash(&buffer);
    buffer.extend_from_slice(hash.as_bytes());
    
    // 9. Atomic write
    write_atomic(path, &buffer)?;
    
    Ok(())
}
```

## Validation Rules

### Critical Checks

```rust
fn validate_file(data: &[u8]) -> Result<()> {
    let file = parse_file(data)?;
    
    // 1. Check all offsets are within bounds
    if file.header.encrypted_rules_offset + file.header.encrypted_rules_length 
       > data.len() as u64 {
        return Err(AionError::InvalidOffset);
    }
    
    // 2. Check sections don't overlap
    let sections = vec![
        (file.header.encrypted_rules_offset, file.header.encrypted_rules_length),
        (file.header.version_chain_offset, file.header.version_chain_count * 152),
        // ... etc
    ];
    check_no_overlap(sections)?;
    
    // 3. Verify version count matches signature count
    if file.header.version_chain_count != file.header.signatures_count {
        return Err(AionError::VersionSignatureMismatch);
    }
    
    // 4. Check version numbers are sequential
    for (i, version) in file.versions.iter().enumerate() {
        if version.version_number != (i + 1) as u64 {
            return Err(AionError::NonSequentialVersions);
        }
    }
    
    // 5. Verify version chain links
    for i in 1..file.versions.len() {
        if file.versions[i].parent_hash != file.versions[i-1].rules_hash {
            return Err(AionError::BrokenVersionChain { version: i as u64 });
        }
    }
    
    Ok(())
}
```

## Endianness

**ALL** multi-byte integers are **little-endian**.

**Rationale:**
- x86/x86-64 (99% of servers/laptops) is little-endian
- ARM (mobile/embedded) typically little-endian
- Network byte order (big-endian) not relevant for file format
- Simplifies zero-copy parsing (no swapping needed)

**Conversion:**
```rust
// Always explicit
let value: u64 = u64::from_le_bytes(bytes);
let bytes: [u8; 8] = value.to_le_bytes();
```

## Alignment

**Natural alignment enforced:**
- 1-byte fields: No alignment
- 2-byte fields: 2-byte aligned
- 4-byte fields: 4-byte aligned  
- 8-byte fields: 8-byte aligned

**Struct packing:**
```rust
#[repr(C)]  // C layout, predictable
struct FileHeader {
    // Natural alignment, no padding needed
}
```

## Extensibility

### Reserved Fields

**All reserved fields MUST be zero.**

**Future versions MAY:**
1. Redefine reserved fields
2. Add new sections (update offsets)
3. Increase version number (trigger migration)

**Version 2 readers encountering version 3:**
- MUST reject file (unsupported version)
- MUST NOT attempt parsing (undefined behavior)
- SHOULD display upgrade message

### Feature Flags

```rust
const FLAG_ENCRYPTED: u16 = 1 << 0;  // Bit 0
const FLAG_COMPRESSED: u16 = 1 << 1; // Bit 1 (reserved)

if header.flags & FLAG_ENCRYPTED != 0 {
    // Encryption enabled
}
```

## Examples

### Minimal File (Genesis)

```
Offset   Hex Values                               Description
──────────────────────────────────────────────────────────────
0x0000   41 49 4F 4E                              Magic: "AION"
0x0004   02 00                                    Version: 2
0x0006   01 00                                    Flags: Encrypted
0x0008   01 00 00 00 00 00 00 00                  File ID: 1
0x0010   01 00 00 00 00 00 00 00                  Current Version: 1
0x0018   [32 bytes root hash]                     Root Hash
0x0038   [32 bytes current hash]                  Current Hash
0x0058   [8 bytes timestamp]                      Created At
0x0060   [8 bytes timestamp]                      Modified At
0x0068   00 01 00 00 00 00 00 00                  Rules Offset: 256
0x0070   1C 04 00 00 00 00 00 00                  Rules Length: 1052
0x0078   1C 05 00 00 00 00 00 00                  Version Chain Offset: 1308
0x0080   01 00 00 00 00 00 00 00                  Version Count: 1
...
0x0100   [12 byte nonce]                          Encryption Nonce
0x010C   [encrypted rules]                        Ciphertext
...      [16 byte tag]                            Auth Tag
...      [152 byte version entry]                 Version 1
...      [112 byte signature]                     Signature 1
...      [80 byte audit entry]                    Audit Entry 1
...      [32 byte hash]                           Integrity Hash
```

## Testing Requirements

### Parser Tests
- Valid file parsing
- Corrupted magic rejection
- Unsupported version rejection
- Overlapping section detection
- Out-of-bounds offset detection

### Round-Trip Tests
```rust
#[test]
fn roundtrip() -> Result<()> {
    let file = create_test_file()?;
    let bytes = serialize_file(&file)?;
    let parsed = parse_file(&bytes)?;
    assert_eq!(file, parsed);
    Ok(())
}
```

### Property Tests
```rust
proptest! {
    #[test]
    fn any_valid_file_parses(file: ValidFile) {
        let bytes = serialize_file(&file)?;
        assert!(parse_file(&bytes).is_ok());
    }
}
```

## References

- [SQLite File Format](https://www.sqlite.org/fileformat.html) (inspiration)
- [Portable Executable Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [ELF Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [zerocopy crate](https://docs.rs/zerocopy/)

---

**This specification is implementation-ready. Any ambiguity is a bug - file an issue.**
