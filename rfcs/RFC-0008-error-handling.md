# RFC 0008: Error Handling Strategy

- **Author:** Reliability Engineer (SRE, 8+ years production systems)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

Comprehensive error handling strategy for AION v2 that guarantees **zero panics** in production, provides **actionable error messages**, enables **debugging**, and maintains **performance**. Every error path is a first-class citizen.

## Motivation

### The Cost of Poor Error Handling

**Real-world incidents:**
1. **Cloudflare 2019:** `unwrap()` on regex compilation → global outage
2. **NPM 2016:** Uncaught exception → registry down 2.5 hours  
3. **AWS S3 2017:** Typo in error handling → cascading failure

**Impact of good error handling:**
- **MTTR:** Mean Time To Recovery reduced 60%
- **Debug Time:** Developer time reduced 80%
- **Customer Trust:** Error messages guide users to solutions

### Design Goals

1. **Zero Panics:** Production code never panics
2. **Contextual Errors:** Every error includes "what/where/why"
3. **Actionable:** Error messages suggest solutions
4. **Debuggable:** Errors include traces for investigation
5. **Type-Safe:** Compiler enforces error handling
6. **Performant:** Zero-cost when no error occurs

## Proposal

### Error Type Hierarchy

```rust
use thiserror::Error;

/// Top-level error type for AION v2
#[derive(Error, Debug)]
pub enum AionError {
    // ============================================================================
    // I/O Errors
    // ============================================================================
    
    #[error("Failed to read file: {path}")]
    FileReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    
    #[error("Failed to write file: {path}")]
    FileWriteError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    
    #[error("File not found: {path}")]
    FileNotFound { path: PathBuf },
    
    #[error("Permission denied: {path}")]
    PermissionDenied { path: PathBuf },
    
    // ============================================================================
    // Format Errors
    // ============================================================================
    
    #[error("Invalid file format: {reason}")]
    InvalidFormat { reason: String },
    
    #[error("Corrupted file: checksum mismatch (expected: {expected}, got: {actual})")]
    CorruptedFile { expected: String, actual: String },
    
    #[error("Unsupported file version: {version} (supported: {supported})")]
    UnsupportedVersion { version: u16, supported: String },
    
    #[error("Invalid header: {reason}")]
    InvalidHeader { reason: String },
    
    // ============================================================================
    // Cryptographic Errors
    // ============================================================================
    
    #[error("Signature verification failed for version {version} by author {author}")]
    SignatureVerificationFailed {
        version: u64,
        author: AuthorId,
    },
    
    #[error("Invalid signature: {reason}")]
    InvalidSignature { reason: String },
    
    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },
    
    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },
    
    #[error("Invalid private key: {reason}")]
    InvalidPrivateKey { reason: String },
    
    #[error("Invalid public key: {reason}")]
    InvalidPublicKey { reason: String },
    
    // ============================================================================
    // Version Chain Errors
    // ============================================================================
    
    #[error("Version chain broken at version {version}: parent hash mismatch")]
    BrokenVersionChain { version: u64 },
    
    #[error("Invalid version number: {version} (current: {current})")]
    InvalidVersionNumber { version: u64, current: u64 },
    
    #[error("Version overflow: cannot increment beyond {max}")]
    VersionOverflow { max: u64 },
    
    #[error("Missing version: {version}")]
    MissingVersion { version: u64 },
    
    // ============================================================================
    // Key Management Errors
    // ============================================================================
    
    #[error("Key not found in keyring: {key_id}")]
    KeyNotFound { key_id: String },
    
    #[error("Keyring access denied: {reason}")]
    KeyringAccessDenied { reason: String },
    
    #[error("Failed to store key: {reason}")]
    KeyStoreFailed { reason: String },
    
    // ============================================================================
    // Validation Errors
    // ============================================================================
    
    #[error("Invalid file ID: {file_id}")]
    InvalidFileId { file_id: u64 },
    
    #[error("Invalid author ID: {author_id}")]
    InvalidAuthorId { author_id: u64 },
    
    #[error("Invalid timestamp: {timestamp}")]
    InvalidTimestamp { timestamp: u64 },
    
    #[error("Rules too large: {size} bytes (max: {max} bytes)")]
    RulesTooLarge { size: usize, max: usize },
    
    // ============================================================================
    // Operational Errors
    // ============================================================================
    
    #[error("Operation not permitted: {operation} requires {required}")]
    OperationNotPermitted {
        operation: String,
        required: String,
    },
    
    #[error("Conflicting operation: {reason}")]
    Conflict { reason: String },
    
    #[error("Resource exhausted: {resource}")]
    ResourceExhausted { resource: String },
}

/// Result type alias for AION operations
pub type Result<T> = std::result::Result<T, AionError>;
```

### Error Context Pattern

**Always add context when propagating:**
```rust
use anyhow::Context;

// ❌ BAD: No context
pub fn load_file(path: &Path) -> Result<File> {
    let bytes = std::fs::read(path)?;
    File::from_bytes(&bytes)?
}

// ✅ GOOD: Rich context
pub fn load_file(path: &Path) -> Result<File> {
    let bytes = std::fs::read(path)
        .with_context(|| format!(
            "Failed to read AION file: {} (check file exists and permissions)",
            path.display()
        ))?;
    
    File::from_bytes(&bytes)
        .with_context(|| format!(
            "Failed to parse AION file: {} (file may be corrupted)",
            path.display()
        ))?
}
```

### Error Recovery Patterns

#### 1. Retry with Exponential Backoff
```rust
pub fn save_with_retry(file: &File, path: &Path, max_retries: u32) -> Result<()> {
    let mut retries = 0;
    let mut delay = Duration::from_millis(100);
    
    loop {
        match file.save(path) {
            Ok(()) => return Ok(()),
            Err(AionError::FileWriteError { .. }) if retries < max_retries => {
                retries += 1;
                tracing::warn!(
                    "Save failed, retrying in {:?} (attempt {}/{})",
                    delay, retries, max_retries
                );
                std::thread::sleep(delay);
                delay *= 2;
            }
            Err(e) => return Err(e),
        }
    }
}
```

#### 2. Fallback to Safe Default
```rust
pub fn load_config_or_default(path: &Path) -> Config {
    match Config::load(path) {
        Ok(config) => config,
        Err(e) => {
            tracing::warn!("Failed to load config: {}, using defaults", e);
            Config::default()
        }
    }
}
```

#### 3. Collect Multiple Errors
```rust
pub fn verify_all_signatures(file: &File) -> Result<()> {
    let mut errors = Vec::new();
    
    for (i, signature) in file.signatures.iter().enumerate() {
        if let Err(e) = verify_signature(file, i) {
            errors.push((i, e));
        }
    }
    
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AionError::MultipleSignatureFailures(errors))
    }
}
```

### Logging Integration

**Always log errors at appropriate level:**
```rust
use tracing::{error, warn, info};

pub fn commit(file: File, rules: &[u8]) -> Result<File> {
    // Trace successful operations
    info!("Committing new version to file {}", file.id());
    
    // Warn on recoverable issues
    if rules.len() > WARNING_SIZE {
        warn!("Rules size {} exceeds recommended limit", rules.len());
    }
    
    // Error on failures
    match file.commit_impl(rules) {
        Ok(new_file) => {
            info!("Successfully committed version {}", new_file.version());
            Ok(new_file)
        }
        Err(e) => {
            error!("Failed to commit: {}", e);
            Err(e)
        }
    }
}
```

### User-Facing Error Messages

**Errors should guide users to solutions:**
```rust
impl std::fmt::Display for AionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::KeyNotFound { key_id } => write!(
                f,
                "Private key not found: {}\n\n\
                 Possible solutions:\n\
                 1. Run 'aion init' to create a new key\n\
                 2. Import existing key with 'aion key import'\n\
                 3. Check if you're using the correct author ID",
                key_id
            ),
            
            Self::SignatureVerificationFailed { version, author } => write!(
                f,
                "Signature verification failed for version {} by author {}\n\n\
                 This file may have been tampered with!\n\
                 DO NOT use this file until the issue is resolved.\n\
                 \n\
                 To investigate:\n\
                 1. Run 'aion verify --verbose <file>' for details\n\
                 2. Check the audit trail with 'aion audit <file>'\n\
                 3. Contact the file author if this is unexpected",
                version, author
            ),
            
            Self::FileWriteError { path, .. } => write!(
                f,
                "Failed to write file: {}\n\n\
                 Possible causes:\n\
                 1. Insufficient disk space\n\
                 2. Permission denied (check directory permissions)\n\
                 3. File is locked by another process\n\
                 4. Read-only file system",
                path.display()
            ),
            
            _ => write!(f, "{}", self),
        }
    }
}
```

## Testing Strategy

### Error Path Coverage

**Every error path must have a test:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_invalid_signature_rejected() -> Result<()> {
        let file = create_test_file()?;
        let mut sig = file.signatures[0].clone();
        sig.signature[0] ^= 1;  // Corrupt signature
        
        let result = verify_signature(&file, 0);
        assert!(matches!(
            result,
            Err(AionError::SignatureVerificationFailed { .. })
        ));
        Ok(())
    }
    
    #[test]
    fn test_file_not_found_error() {
        let result = File::load(Path::new("/nonexistent/file.aion"));
        assert!(matches!(result, Err(AionError::FileNotFound { .. })));
    }
    
    #[test]
    fn test_error_message_contains_path() {
        let path = PathBuf::from("/test/file.aion");
        let error = AionError::FileNotFound { path: path.clone() };
        let message = error.to_string();
        assert!(message.contains("/test/file.aion"));
    }
}
```

### Property-Based Error Tests

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn no_panic_on_invalid_input(bytes: Vec<u8>) {
        // Must return error, not panic
        let _ = File::from_bytes(&bytes);
    }
    
    #[test]
    fn error_roundtrip(error: AionError) {
        // Error can be serialized and displayed
        let message = error.to_string();
        assert!(!message.is_empty());
    }
}
```

## Implementation Plan

### Phase 1: Core Error Types (Week 1)
- [ ] Define `AionError` enum
- [ ] Implement `Display` for user messages
- [ ] Add `thiserror` derives
- [ ] Write error construction tests

### Phase 2: Integration (Week 2)
- [ ] Replace all `unwrap()` with error handling
- [ ] Add context to error propagation
- [ ] Integrate with logging
- [ ] Write error path tests

### Phase 3: Documentation (Week 3)
- [ ] Document each error variant
- [ ] Create error handling guide
- [ ] Add troubleshooting docs
- [ ] User-facing error catalog

## Open Questions

1. **Should we include stack traces in errors?**
   - Helpful for debugging
   - But large and scary for users
   - **Recommendation:** Only in debug builds

2. **Error telemetry/reporting?**
   - Helps identify common errors
   - Privacy concerns
   - **Recommendation:** Opt-in only (RFC-0024)

## References

- [Rust Error Handling Survey](https://blog.burntsushi.net/rust-error-handling/)
- [thiserror crate](https://docs.rs/thiserror/)
- [anyhow crate](https://docs.rs/anyhow/)

---

**Key Principle:** Every error is an opportunity to help the user succeed.
