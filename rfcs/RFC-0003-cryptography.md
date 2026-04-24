# RFC 0003: Cryptographic Specifications

- **Author:** Senior Cryptographer (PhD, 15+ years applied cryptography)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

This RFC specifies cryptographic primitives, protocols, and security parameters for AION v2. All choices prioritize **proven security**, **implementation simplicity**, and **performance**. We favor battle-tested algorithms over novel constructions.

## Motivation

### Security Requirements

1. **Integrity:** Detect any file modification
2. **Authenticity:** Verify author identity  
3. **Non-Repudiation:** Authors cannot deny signatures
4. **Confidentiality:** Protect rules content (optional)
5. **Forward Secrecy:** Compromised key doesn't expose past versions

### Threat Model

**Adversary Capabilities:**
- Read/write file system
- Network access (for sync)
- Computational power: 2^80 operations feasible, 2^128 infeasible
- Quantum computer: Not currently available (plan for future)

**Out of Scope:**
- Side-channel attacks on user's machine
- Physical security of storage media
- Social engineering of authors

## Proposal

### Algorithm Selection

#### Digital Signatures: Ed25519

**Choice:** EdDSA with Curve25519 (Ed25519)

**Rationale:**
- **Security:** 128-bit security level (equivalent to RSA-3072)
- **Performance:** 20x faster than ECDSA, 100x faster than RSA
- **Size:** 32-byte public key, 64-byte signature (vs 256-byte RSA)
- **Simplicity:** No parameter choice, no nonce generation pitfalls
- **Implementation:** Constant-time by design, resistant to timing attacks

**Parameters:**
```rust
Public Key:  32 bytes (Curve25519 point)
Private Key: 32 bytes (scalar)
Signature:   64 bytes (R || s)
Security:    2^128 operations to forge
```

**Library:** `ed25519-dalek` v2.x (pure Rust, audited)

#### Encryption: ChaCha20-Poly1305

**Choice:** ChaCha20 stream cipher with Poly1305 authenticator (AEAD)

**Rationale:**
- **Security:** 256-bit key, 96-bit nonce, 128-bit authentication tag
- **Performance:** 3-5x faster than AES-GCM on non-AES-NI CPUs
- **Simplicity:** No padding oracle vulnerabilities (stream cipher)
- **Safety:** AEAD provides authenticated encryption
- **Standard:** RFC 8439, TLS 1.3 mandatory cipher

**Parameters:**
```rust
Key:    32 bytes (256 bits)
Nonce:  12 bytes (96 bits) - MUST be unique per encryption
Tag:    16 bytes (128-bit Poly1305 MAC)
Security: 2^128 operations to break confidentiality/authenticity
```

**Library:** `chacha20poly1305` v0.10 (RustCrypto, audited)

#### Hashing: BLAKE3

**Choice:** BLAKE3 cryptographic hash function

**Rationale:**
- **Speed:** 5x faster than SHA-256, parallelizable
- **Security:** 256-bit output, collision resistance 2^128
- **Versatility:** Also serves as KDF, MAC, PRF
- **Modern:** Designed 2020, incorporates latest research
- **Tree Mode:** Supports incremental hashing

**Parameters:**
```rust
Output:  32 bytes (256 bits) default
Security: 2^128 collision resistance, 2^256 preimage
```

**Library:** `blake3` v1.x (official Rust implementation)

#### Key Derivation: HKDF-SHA256

**Choice:** HMAC-based Extract-and-Expand Key Derivation Function

**Rationale:**
- **Standard:** RFC 5869, NIST approved
- **Simplicity:** Well-understood construction
- **Versatility:** Derives multiple keys from single master
- **Security:** Proven reduction to HMAC security

**Parameters:**
```rust
Hash:   SHA-256 (for FIPS 140-2 compatibility)
Salt:   32 bytes (optional but recommended)
Info:   Context string (e.g., "aion-context-version-key")
Output: Arbitrary length (we use 32 bytes)
```

**Library:** `hkdf` v0.12 (RustCrypto)

### Cryptographic Protocols

#### Version Signing Protocol

**Goal:** Prove version was created by specific author

**Protocol:**
```
1. Author creates VersionEntry V = {version_num, parent_hash, rules_hash, author_id, timestamp, message}
2. Serialize V to canonical bytes: data = serialize(V)
3. Compute hash: h = BLAKE3(data)
4. Sign hash: sig = Ed25519_Sign(private_key, h)
5. Store signature: Signature {author_id, public_key, sig, h}
```

**Security Properties:**
- **Unforgeability:** Ed25519 provides EUF-CMA (Existential Unforgeability under Chosen Message Attack)
- **Uniqueness:** Each version signed independently
- **Binding:** Signature includes parent_hash, creating chain

**Verification:**
```
1. Load signature S
2. Recompute hash: h' = BLAKE3(serialize(V))
3. Verify: Ed25519_Verify(S.public_key, h', S.sig)
4. Check: h' == S.signed_data_hash
5. Accept if both checks pass
```

#### Rule Encryption Protocol

**Goal:** Protect confidentiality of rules content

**Key Hierarchy:**
```
file_id (64 bits)
    └─> Master Key = HKDF(salt=file_id, ikm=random_seed, info="aion-master")
            └─> Version Key(v) = HKDF(salt=Master, ikm=version_num, info="aion-version-N")
                    └─> Encryption Key = Version Key
```

**Encryption:**
```
1. Derive key: K = derive_version_key(file_id, version_num)
2. Generate nonce: N = random(12 bytes) - MUST be unique
3. Encrypt: C = ChaCha20-Poly1305_Encrypt(K, N, rules, aad=header)
4. Store: {nonce || ciphertext || tag}
```

**Additional Authenticated Data (AAD):**
```rust
aad = file_id || version_number || rules_hash
```
This binds ciphertext to specific version, preventing version confusion attacks.

**Decryption:**
```
1. Derive same key: K = derive_version_key(file_id, version_num)
2. Extract nonce: N = ciphertext[0..12]
3. Decrypt: rules = ChaCha20-Poly1305_Decrypt(K, N, ciphertext[12..], aad)
4. Verify hash: BLAKE3(rules) == rules_hash (defense in depth)
```

### Security Parameters

#### Recommended Lifetimes

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Private Key Rotation | 1-2 years | Balance security/convenience |
| File Master Key | Never rotate | Backward compatibility |
| Nonce Reuse | NEVER | Catastrophic failure mode |
| Signature Algorithm | 10+ years | Ed25519 post-quantum upgrade path |

#### Entropy Requirements

**Private Key Generation:**
```rust
use rand::rngs::OsRng;
let signing_key = SigningKey::generate(&mut OsRng);
```
- **Source:** OS-provided CSPRNG (`/dev/urandom`, `CryptGenRandom`, etc.)
- **Entropy:** Full 256 bits
- **Validation:** Run entropy tests (NIST SP 800-90B)

**Nonce Generation:**
```rust
use rand::RngCore;
let mut nonce = [0u8; 12];
OsRng.fill_bytes(&mut nonce);
```
- **Critical:** Nonce reuse breaks ChaCha20-Poly1305
- **Mitigation:** Use random nonce + enforce uniqueness check

### Implementation Guidelines

#### Constant-Time Operations

**REQUIRED for crypto comparisons:**
```rust
use subtle::ConstantTimeEq;

// ✅ CORRECT: Constant-time
if signature1.ct_eq(&signature2).unwrap_u8() == 1 {
    // Signatures match
}

// ❌ FORBIDDEN: Variable-time (timing attack)
if signature1 == signature2 {
    // Vulnerable!
}
```

#### Secure Memory Handling

**REQUIRED for all key material:**
```rust
use zeroize::{Zeroize, Zeroizing};

// ✅ CORRECT: Automatic zeroing
let private_key = Zeroizing::new(load_key()?);
// Key automatically zeroed when dropped

// Manual zeroing if needed
let mut buffer = vec![0u8; 32];
// ... use buffer ...
buffer.zeroize();
```

#### Panic-Free Crypto

**NEVER panic in crypto code:**
```rust
// ❌ FORBIDDEN
fn sign(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(key).unwrap(); // Can panic!
    signing_key.sign(msg).to_bytes()
}

// ✅ CORRECT
fn sign(key: &[u8], msg: &[u8]) -> Result<[u8; 64]> {
    let signing_key = SigningKey::from_bytes(key)
        .map_err(|_| AionError::InvalidPrivateKey)?;
    Ok(signing_key.sign(msg).to_bytes())
}
```

## Security Analysis

### Attack Scenarios

#### 1. Signature Forgery Attack

**Attack:** Adversary tries to forge author signature

**Mitigation:**
- Ed25519 provides 128-bit security
- Requires 2^128 operations (computationally infeasible)
- Even quantum computer needs 2^64 operations (Grover's algorithm)

**Residual Risk:** Post-quantum vulnerability (address in RFC-0021)

#### 2. Ciphertext Manipulation

**Attack:** Adversary modifies encrypted rules

**Mitigation:**
- Poly1305 MAC authenticates ciphertext
- AAD binds to version metadata
- Decryption fails if ANY byte modified

**Residual Risk:** None (assuming ChaCha20-Poly1305 security)

#### 3. Version Rollback Attack

**Attack:** Adversary replaces file with older version

**Mitigation:**
- Version chain links parent_hash → current_hash
- Verification detects broken chain
- Application-level checks for version number

**Residual Risk:** If application doesn't verify, rollback possible

#### 4. Key Extraction from Memory

**Attack:** Memory dump reveals private key

**Mitigation:**
- Zeroize immediately after use
- OS keyring encryption at rest
- No swap for sensitive memory (future enhancement)

**Residual Risk:** Moderate (OS-dependent)

### Cryptanalysis Resistance

**Ed25519:**
- Secure against known attack classes
- No special prime or parameter backdoors
- Rigidity in design (minimal parameter choices)
- Widely deployed (OpenSSH, Signal, Tor)

**ChaCha20-Poly1305:**
- No known practical attacks
- Recommended by Google Project Zero
- Mandatory in TLS 1.3
- Simpler than AES-GCM (fewer pitfalls)

**BLAKE3:**
- Based on BLAKE2 (SHA-3 finalist)
- Extensive cryptanalysis (no weaknesses found)
- Margin: 16 rounds (vs 10 in SHA-2)

## Performance Targets

### Benchmarks (Intel i7-9750H, single-threaded)

```
Operation                     Time       Throughput
──────────────────────────────────────────────────────
Ed25519 Sign                  45 µs      22,000 ops/sec
Ed25519 Verify                140 µs     7,100 ops/sec
ChaCha20-Poly1305 Encrypt     0.7 µs/KB  1.4 GB/sec
ChaCha20-Poly1305 Decrypt     0.7 µs/KB  1.4 GB/sec
BLAKE3 Hash                   0.2 µs/KB  5.0 GB/sec
HKDF Derive (32-byte output)  2 µs       500,000 ops/sec
```

### Optimization Strategies

1. **Batch Signature Verification:** Use `ed25519-dalek` batch API (3x faster)
2. **SIMD Instructions:** BLAKE3 auto-detects AVX2/AVX-512
3. **Parallel Hashing:** BLAKE3 tree mode for >1MB files
4. **Key Caching:** Derive version keys once, cache in memory

## Testing Strategy

### Test Vectors

**Required test vectors (from standards):**
- Ed25519: RFC 8032 Appendix A
- ChaCha20-Poly1305: RFC 8439 Appendix A
- BLAKE3: Official test vectors
- HKDF: RFC 5869 Appendix A

### Property-Based Tests

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn signature_roundtrip(data: Vec<u8>) {
        let key = SigningKey::generate(&mut OsRng);
        let sig = key.sign(&data);
        assert!(key.verifying_key().verify(&data, &sig).is_ok());
    }
    
    #[test]
    fn encryption_roundtrip(plaintext: Vec<u8>) {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }
}
```

### Security Tests

**Negative Tests (must fail):**
```rust
#[test]
fn modified_ciphertext_fails() {
    let encrypted = encrypt(key, plaintext);
    encrypted[0] ^= 1;  // Flip one bit
    assert!(decrypt(key, encrypted).is_err());  // Must fail
}

#[test]
fn wrong_key_fails() {
    let encrypted = encrypt(key1, plaintext);
    assert!(decrypt(key2, encrypted).is_err());  // Must fail
}

#[test]
fn invalid_signature_fails() {
    let mut sig = sign(key, message);
    sig[0] ^= 1;  // Corrupt signature
    assert!(verify(public_key, message, sig).is_err());
}
```

## Implementation Plan

### Phase 1: Core Primitives (Week 1)
- [ ] Integrate Ed25519 (ed25519-dalek)
- [ ] Integrate ChaCha20-Poly1305 (chacha20poly1305)
- [ ] Integrate BLAKE3 (blake3)
- [ ] Integrate HKDF (hkdf)
- [ ] Write wrapper API

### Phase 2: Protocols (Week 2)
- [ ] Implement version signing protocol
- [ ] Implement encryption protocol
- [ ] Key derivation hierarchy
- [ ] Nonce management

### Phase 3: Testing (Week 3)
- [ ] Test vector validation
- [ ] Property-based tests
- [ ] Negative test cases
- [ ] Performance benchmarks

### Phase 4: Security Review (Week 4)
- [ ] External audit (if budget allows)
- [ ] Constant-time verification
- [ ] Side-channel analysis
- [ ] Documentation review

## Open Questions

1. **Should we support symmetric key pre-distribution?**
   - Some orgs want shared keys vs asymmetric
   - Adds complexity but enables team workflows
   - **Recommendation:** Defer to RFC-0014 (Multi-Signature)

2. **Post-quantum cryptography timeline?**
   - NIST standards expected 2024
   - Migration path needed before quantum computers viable
   - **Recommendation:** Plan now (RFC-0021), implement when standards stable

3. **Hardware security module (HSM) integration?**
   - Enterprise customers may require HSM
   - Adds significant complexity
   - **Recommendation:** Optional future enhancement (RFC-0023)

## References

- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 8439: ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [DJB's Crypto Failures](https://cr.yp.to/talks.html)
- [NaCl: Networking and Cryptography library](https://nacl.cr.yp.to/)

## Appendix A: Cryptographic Code Examples

### Complete Signing Example
```rust
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

pub fn sign_version(
    version: &VersionEntry,
    private_key: &Zeroizing<SigningKey>,
) -> Result<Signature> {
    // Serialize version to canonical bytes
    let mut buf = Vec::with_capacity(256);
    version.serialize(&mut buf)?;
    
    // Hash the serialized data
    let hash = blake3::hash(&buf);
    
    // Sign the hash
    let signature = private_key.sign(hash.as_bytes());
    
    Ok(Signature {
        author_id: version.author_id,
        public_key: private_key.verifying_key().to_bytes(),
        signature: signature.to_bytes(),
        signed_data_hash: *hash.as_bytes(),
    })
}
```

### Complete Encryption Example
```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};

pub fn encrypt_rules(
    rules: &[u8],
    file_id: FileId,
    version: u64,
) -> Result<Vec<u8>> {
    // Derive version-specific key
    let key = derive_version_key(file_id, version)?;
    let cipher = ChaCha20Poly1305::new(&key);
    
    // Generate random nonce
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    
    // Construct AAD (binds to version)
    let aad = construct_aad(file_id, version);
    
    // Encrypt
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: rules, aad: &aad })
        .map_err(|_| AionError::EncryptionFailed)?;
    
    // Prepend nonce to ciphertext
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    
    Ok(output)
}
```

This completes the cryptographic specification for AION v2.
