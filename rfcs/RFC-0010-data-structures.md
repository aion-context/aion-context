# RFC 0010: Core Data Structures

- **Author:** Data Architect (Rust expert, 8+ years)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

Complete Rust type definitions for AION v2. These are **production-ready structs** with proper derives, documentation, and invariants. Copy-paste into your codebase and start coding.

## Core Types

### Type Aliases and Newtypes

```rust
//! Type-safe identifiers prevent mixing up parameters

use std::fmt;

/// Unique file identifier (64-bit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct FileId(pub u64);

impl FileId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    
    pub fn random() -> Self {
        Self(rand::random())
    }
    
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

/// Author identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthorId(pub u64);

impl fmt::Display for AuthorId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Version number (monotonically increasing)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct VersionNumber(pub u64);

impl VersionNumber {
    pub const GENESIS: Self = Self(1);
    
    pub fn next(self) -> Result<Self> {
        self.0.checked_add(1)
            .map(Self)
            .ok_or(AionError::VersionOverflow { max: self.0 })
    }
    
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for VersionNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 256-bit hash (BLAKE3)
pub type Hash = [u8; 32];

/// Ed25519 public key
pub type PublicKey = [u8; 32];

/// Ed25519 signature
pub type Signature = [u8; 64];
```

### File Header

```rust
use zerocopy::{AsBytes, FromBytes, FromZeroes};

/// Fixed 256-byte file header
#[derive(Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct FileHeader {
    /// Magic number: "AION" (0x41494F4E)
    pub magic: [u8; 4],
    
    /// Format version (current: 2)
    pub version: u16,
    
    /// Feature flags (bit 0: encrypted)
    pub flags: u16,
    
    /// Unique file identifier
    pub file_id: u64,
    
    /// Current version number
    pub current_version: u64,
    
    /// Root hash (genesis version)
    pub root_hash: Hash,
    
    /// Current version hash
    pub current_hash: Hash,
    
    /// Creation timestamp (nanoseconds since Unix epoch)
    pub created_at: u64,
    
    /// Last modification timestamp
    pub modified_at: u64,
    
    /// Encrypted rules section offset
    pub encrypted_rules_offset: u64,
    
    /// Encrypted rules length (bytes)
    pub encrypted_rules_length: u64,
    
    /// Version chain section offset
    pub version_chain_offset: u64,
    
    /// Number of version entries
    pub version_chain_count: u64,
    
    /// Signatures section offset
    pub signatures_offset: u64,
    
    /// Number of signatures
    pub signatures_count: u64,
    
    /// Audit trail section offset
    pub audit_trail_offset: u64,
    
    /// Number of audit entries
    pub audit_trail_count: u64,
    
    /// String table offset
    pub string_table_offset: u64,
    
    /// String table length
    pub string_table_length: u64,
    
    /// Reserved for future use (must be zero)
    pub reserved: [u8; 72],
}

const _: () = assert!(std::mem::size_of::<FileHeader>() == 256);

impl FileHeader {
    pub const MAGIC: &'static [u8; 4] = b"AION";
    pub const VERSION: u16 = 2;
    pub const FLAG_ENCRYPTED: u16 = 1 << 0;
    
    pub fn new(file_id: FileId) -> Self {
        let now = current_timestamp();
        
        Self {
            magic: *Self::MAGIC,
            version: Self::VERSION,
            flags: Self::FLAG_ENCRYPTED,
            file_id: file_id.0,
            current_version: 1,
            root_hash: [0; 32],
            current_hash: [0; 32],
            created_at: now,
            modified_at: now,
            encrypted_rules_offset: 256, // After header
            encrypted_rules_length: 0,
            version_chain_offset: 0,
            version_chain_count: 0,
            signatures_offset: 0,
            signatures_count: 0,
            audit_trail_offset: 0,
            audit_trail_count: 0,
            string_table_offset: 0,
            string_table_length: 0,
            reserved: [0; 72],
        }
    }
    
    pub fn validate(&self) -> Result<()> {
        if &self.magic != Self::MAGIC {
            return Err(AionError::InvalidMagic);
        }
        if self.version != Self::VERSION {
            return Err(AionError::UnsupportedVersion { version: self.version });
        }
        if self.version_chain_count != self.signatures_count {
            return Err(AionError::VersionSignatureMismatch);
        }
        Ok(())
    }
    
    pub fn is_encrypted(&self) -> bool {
        self.flags & Self::FLAG_ENCRYPTED != 0
    }
}
```

### Version Entry

```rust
/// Fixed 152-byte version entry
#[derive(Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct VersionEntry {
    /// Version number (1, 2, 3, ...)
    pub version_number: u64,
    
    /// Parent version hash (genesis: all zeros)
    pub parent_hash: Hash,
    
    /// This version's rules hash
    pub rules_hash: Hash,
    
    /// Author who created this version
    pub author_id: u64,
    
    /// Creation timestamp
    pub timestamp: u64,
    
    /// Commit message offset in string table
    pub message_offset: u64,
    
    /// Commit message length
    pub message_length: u32,
    
    /// Reserved
    pub reserved: [u8; 52],
}

const _: () = assert!(std::mem::size_of::<VersionEntry>() == 152);

impl VersionEntry {
    pub fn genesis(
        author: AuthorId,
        rules_hash: Hash,
        message_offset: u64,
        message_length: u32,
    ) -> Self {
        Self {
            version_number: 1,
            parent_hash: [0; 32],
            rules_hash,
            author_id: author.0,
            timestamp: current_timestamp(),
            message_offset,
            message_length,
            reserved: [0; 52],
        }
    }
    
    pub fn next_version(
        parent: &Self,
        author: AuthorId,
        rules_hash: Hash,
        message_offset: u64,
        message_length: u32,
    ) -> Result<Self> {
        let next_version = parent.version_number.checked_add(1)
            .ok_or(AionError::VersionOverflow { max: parent.version_number })?;
        
        Ok(Self {
            version_number: next_version,
            parent_hash: parent.rules_hash,
            rules_hash,
            author_id: author.0,
            timestamp: current_timestamp(),
            message_offset,
            message_length,
            reserved: [0; 52],
        })
    }
}
```

### Signature Entry

```rust
/// Fixed 112-byte signature entry
#[derive(Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct SignatureEntry {
    /// Author who signed
    pub author_id: u64,
    
    /// Ed25519 public key
    pub public_key: PublicKey,
    
    /// Ed25519 signature (signs BLAKE3(VersionEntry))
    pub signature: Signature,
    
    /// Reserved
    pub reserved: [u8; 8],
}

const _: () = assert!(std::mem::size_of::<SignatureEntry>() == 112);
```

### Audit Entry

```rust
/// Fixed 80-byte audit entry
#[derive(Clone, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct AuditEntry {
    /// Timestamp
    pub timestamp: u64,
    
    /// Author who performed action
    pub author_id: u64,
    
    /// Action code (enum)
    pub action_code: u16,
    
    /// Reserved
    pub reserved1: [u8; 6],
    
    /// Details string offset
    pub details_offset: u64,
    
    /// Details string length
    pub details_length: u32,
    
    /// Reserved
    pub reserved2: [u8; 4],
    
    /// Previous entry hash (chain)
    pub previous_hash: Hash,
    
    /// Reserved
    pub reserved3: [u8; 8],
}

const _: () = assert!(std::mem::size_of::<AuditEntry>() == 80);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AuditAction {
    CreateGenesis = 1,
    CommitVersion = 2,
    Verify = 3,
    Inspect = 4,
}
```

### High-Level File Structure

```rust
/// In-memory representation of AION file
pub struct AionFile {
    pub header: FileHeader,
    pub encrypted_rules: Vec<u8>,
    pub versions: Vec<VersionEntry>,
    pub signatures: Vec<SignatureEntry>,
    pub audit_trail: Vec<AuditEntry>,
    pub string_table: Vec<u8>,
}

impl AionFile {
    /// Create new genesis file
    pub fn new(file_id: FileId) -> Self {
        Self {
            header: FileHeader::new(file_id),
            encrypted_rules: Vec::new(),
            versions: Vec::new(),
            signatures: Vec::new(),
            audit_trail: Vec::new(),
            string_table: Vec::new(),
        }
    }
    
    /// Load from disk
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        Self::from_bytes(&data)
    }
    
    /// Parse from bytes (see RFC-0002)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        parse_file(data)
    }
    
    /// Save to disk
    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = self.to_bytes()?;
        write_atomic(path, &bytes)
    }
    
    /// Serialize to bytes (see RFC-0002)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serialize_file(self)
    }
    
    /// Get current version number
    pub fn current_version(&self) -> VersionNumber {
        VersionNumber(self.header.current_version)
    }
    
    /// Get file ID
    pub fn file_id(&self) -> FileId {
        FileId(self.header.file_id)
    }
    
    /// Verify signature chain
    pub fn verify(&self) -> Result<()> {
        verify_signature_chain(self)
    }
}
```

## Helper Functions

```rust
use std::time::{SystemTime, UNIX_EPOCH};

/// Get current timestamp in nanoseconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before Unix epoch")
        .as_nanos() as u64
}

/// Atomic file write (write to temp, then rename)
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    use std::fs;
    use std::io::Write;
    
    let temp_path = path.with_extension("tmp");
    
    let mut file = fs::File::create(&temp_path)
        .with_context(|| format!("Failed to create temp file: {}", temp_path.display()))?;
    
    file.write_all(data)
        .with_context(|| format!("Failed to write temp file: {}", temp_path.display()))?;
    
    file.sync_all()
        .context("Failed to sync temp file to disk")?;
    
    fs::rename(&temp_path, path)
        .with_context(|| format!(
            "Failed to rename {} to {}",
            temp_path.display(),
            path.display()
        ))?;
    
    Ok(())
}
```

## Complete Example

```rust
use aion_context::*;

fn main() -> Result<()> {
    // Generate author key
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let author = AuthorId(50001);
    
    // Create genesis file
    let file_id = FileId::random();
    let mut file = AionFile::new(file_id);
    
    // Add rules
    let rules = b"rule: no_fraud\nrule: prior_auth_required";
    let rules_hash = blake3::hash(rules);
    
    // Create version entry
    file.string_table.extend_from_slice(b"Genesis version\0");
    let version = VersionEntry::genesis(
        author,
        *rules_hash.as_bytes(),
        0,
        15,
    );
    
    // Sign version
    let signature = signing_key.sign(version.as_bytes());
    let sig_entry = SignatureEntry {
        author_id: author.0,
        public_key: signing_key.verifying_key().to_bytes(),
        signature: signature.to_bytes(),
        reserved: [0; 8],
    };
    
    // Encrypt rules
    file.encrypted_rules = encrypt_rules(rules, file_id, VersionNumber::GENESIS)?;
    
    // Update file
    file.header.root_hash = *rules_hash.as_bytes();
    file.header.current_hash = *rules_hash.as_bytes();
    file.versions.push(version);
    file.signatures.push(sig_entry);
    
    // Save
    file.save(Path::new("healthcare.aion"))?;
    
    println!("✓ Created file: {}", file_id);
    
    // Load and verify
    let loaded = AionFile::load(Path::new("healthcare.aion"))?;
    loaded.verify()?;
    
    println!("✓ Signature verified");
    
    Ok(())
}
```

This RFC provides complete, copy-pasteable type definitions for AION v2 implementation.
