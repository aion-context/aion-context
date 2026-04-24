# RFC 0004: Key Management & OS Keyring Integration

- **Author:** Security Engineer  
- **Status:** DRAFT
- **Created:** 2024-11-23

## Abstract

Secure key management using OS-provided credential storage. Private keys stay on user's machine, protected by OS-level encryption.

## Key Storage

**Platform Support:**
- **macOS:** Keychain (AES-256, hardware-backed)
- **Windows:** Credential Manager (DPAPI)
- **Linux:** Secret Service API (gnome-keyring)
- **Fallback:** Encrypted file with warning

## Implementation

```rust
use keyring::Entry;
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

/// Store private key in OS keyring
pub fn store_private_key(author_id: AuthorId, key: &SigningKey) -> Result<()> {
    let entry = Entry::new("aion-context", &format!("author-{}", author_id.0))?;
    entry.set_password(&hex::encode(key.to_bytes()))?;
    Ok(())
}

/// Load private key (auto-zeroizing)
pub fn load_private_key(author_id: AuthorId) -> Result<Zeroizing<SigningKey>> {
    let entry = Entry::new("aion-context", &format!("author-{}", author_id.0))?;
    let key_hex = entry.get_password()?;
    let key_bytes = hex::decode(&key_hex)?;
    
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    
    Ok(Zeroizing::new(SigningKey::from_bytes(&key_array)))
}
```

## CLI Commands

```bash
# Initialize
$ aion init --author-id 50001
✓ Private key stored in system keyring
✓ Public key: a3f7b8...

# Export for backup
$ aion key export --author-id 50001
Password: ********
✓ Exported to author-50001.key

# Import from backup  
$ aion key import author-50001.key
Password: ********
✓ Imported author 50001
```

## Security

- Keys never written to disk in plaintext
- Automatic zeroization after use
- OS-level access control
- Optional password-encrypted backups

This completes the key management specification.
