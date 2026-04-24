# RFC 0013: Optional Cloud Sync Protocol

- **Author:** Distributed Systems Engineer (12+ years P2P protocols, blockchain consensus)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

Specification for optional cloud synchronization protocol in AION v2. Enables secure, conflict-free synchronization of AION files across multiple devices and cloud storage providers while maintaining the offline-first design principle. All synchronization is cryptographically secured and preserves the complete audit trail.

## Motivation

### Problem Statement

While AION v2 is designed for offline-first operation, users often need to:

1. **Multi-Device Access:** Work with same files across laptop, desktop, mobile
2. **Team Collaboration:** Share files with colleagues while maintaining security
3. **Backup & Recovery:** Store encrypted backups in cloud storage
4. **Remote Access:** Access files from different locations
5. **Conflict Resolution:** Handle simultaneous edits from multiple devices

### Design Goals

- **Optional by Design:** Sync is opt-in, files work perfectly without it
- **End-to-End Encryption:** Cloud provider never sees plaintext data
- **Conflict-Free:** Deterministic merge resolution preserves all changes
- **Provider Agnostic:** Works with any cloud storage (S3, Google Drive, Dropbox)
- **Bandwidth Efficient:** Only sync changed versions, not entire files
- **Audit Trail Preservation:** Complete history maintained across all devices

### Non-Goals

- **Real-time Collaboration:** Not optimized for simultaneous editing
- **Cloud Computation:** No server-side processing, pure storage
- **User Management:** No built-in access control beyond encryption
- **Conflict Prevention:** Conflicts are resolved, not prevented

## Proposal

### Sync Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Device A      │    │   Cloud Store   │    │   Device B      │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ AION File   │◄┼────┼─│ Sync Repo   │─┼────┼►│ AION File   │ │
│ │ (Local)     │ │    │ │ (Encrypted) │ │    │ │ (Local)     │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Sync Engine │ │    │ │ Manifest    │ │    │ │ Sync Engine │ │
│ │             │ │    │ │ (Metadata)  │ │    │ │             │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Sync Repository Structure

Cloud storage contains encrypted, content-addressed objects:

```
sync-repo-{file-id}/
├── manifest.json.enc              # Repository metadata
├── objects/
│   ├── {hash1}.blob              # Encrypted version data
│   ├── {hash2}.blob              # Encrypted signature data
│   └── {hash3}.blob              # Encrypted audit entries
└── refs/
    ├── heads/device-{device-id}  # Per-device head pointers
    └── remotes/                  # Remote device tracking
```

### Data Model

#### Sync Repository

```rust
/// Cloud sync repository for a single AION file
#[derive(Debug, Clone)]
pub struct SyncRepository {
    /// Unique file identifier
    pub file_id: FileId,
    
    /// Repository encryption key
    pub repo_key: ChaCha20Key,
    
    /// All devices with access
    pub devices: HashMap<DeviceId, DeviceInfo>,
    
    /// Content-addressed object store
    pub objects: ObjectStore,
    
    /// References to current state per device
    pub refs: RefStore,
}

/// Individual device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: DeviceId,
    pub public_key: [u8; 32],        // Device signing key
    pub last_seen: u64,              // Unix timestamp
    pub capabilities: DeviceCapabilities,
}

/// Encrypted object in cloud storage
#[derive(Debug, Clone)]
pub struct SyncObject {
    pub object_id: ObjectId,         // Content hash
    pub encrypted_data: Vec<u8>,     // ChaCha20-Poly1305 encrypted
    pub nonce: [u8; 12],            // Unique per object
    pub auth_tag: [u8; 16],         // Integrity protection
}
```

#### Sync Protocol Messages

```rust
/// Protocol messages for sync operations
#[derive(Debug, Clone)]
pub enum SyncMessage {
    /// Request repository metadata
    GetManifest {
        file_id: FileId,
    },
    
    /// Repository metadata response
    Manifest {
        file_id: FileId,
        devices: Vec<DeviceInfo>,
        object_count: u64,
        total_size: u64,
    },
    
    /// Request specific objects
    GetObjects {
        object_ids: Vec<ObjectId>,
    },
    
    /// Objects response
    Objects {
        objects: Vec<SyncObject>,
    },
    
    /// Push new objects
    PushObjects {
        objects: Vec<SyncObject>,
    },
    
    /// Update device head reference
    UpdateRef {
        device_id: DeviceId,
        head_object: ObjectId,
        signature: [u8; 64],         // Sign ref update
    },
    
    /// Sync completion acknowledgment
    SyncComplete {
        device_id: DeviceId,
        synced_objects: u64,
    },
}
```

### Synchronization Protocol

#### Phase 1: Discovery

```rust
impl SyncEngine {
    /// Initialize sync for a file
    pub async fn initialize_sync(
        &mut self,
        file_id: FileId,
        cloud_provider: &dyn CloudProvider,
    ) -> Result<SyncRepository> {
        // Check if sync repo already exists
        match cloud_provider.get_manifest(file_id).await {
            Ok(manifest) => {
                // Join existing sync repository
                self.join_sync_repository(file_id, manifest).await
            }
            Err(CloudError::NotFound) => {
                // Create new sync repository
                self.create_sync_repository(file_id, cloud_provider).await
            }
            Err(e) => Err(e.into()),
        }
    }
    
    /// Create new sync repository
    async fn create_sync_repository(
        &mut self,
        file_id: FileId,
        cloud_provider: &dyn CloudProvider,
    ) -> Result<SyncRepository> {
        // Generate repository encryption key
        let repo_key = ChaCha20Key::generate();
        
        // Create device info for this device
        let device_info = DeviceInfo {
            device_id: self.device_id,
            public_key: self.device_keypair.public.to_bytes(),
            last_seen: unix_timestamp(),
            capabilities: DeviceCapabilities::default(),
        };
        
        // Create initial manifest
        let manifest = SyncManifest {
            file_id,
            repo_key: repo_key.clone(),
            devices: vec![device_info],
            created_at: unix_timestamp(),
            version: 1,
        };
        
        // Encrypt and upload manifest
        let encrypted_manifest = encrypt_manifest(&manifest, &repo_key)?;
        cloud_provider.put_manifest(file_id, encrypted_manifest).await?;
        
        Ok(SyncRepository {
            file_id,
            repo_key,
            devices: HashMap::from([(self.device_id, device_info)]),
            objects: ObjectStore::new(),
            refs: RefStore::new(),
        })
    }
}
```

#### Phase 2: Upload Local Changes

```rust
impl SyncEngine {
    /// Upload local changes to cloud
    pub async fn push_changes(
        &mut self,
        file: &AionFile,
        cloud_provider: &dyn CloudProvider,
    ) -> Result<PushResult> {
        let file_id = file.file_id();
        let repo = self.get_repository(file_id)?;
        
        // Find versions not yet in cloud
        let local_versions = file.get_all_versions();
        let remote_objects = self.fetch_object_list(&repo, cloud_provider).await?;
        let missing_versions = self.find_missing_versions(&local_versions, &remote_objects);
        
        if missing_versions.is_empty() {
            return Ok(PushResult::NothingToPush);
        }
        
        // Create encrypted objects for missing versions
        let mut objects_to_push = Vec::new();
        
        for version in missing_versions {
            // Create version object
            let version_data = version.serialize()?;
            let version_object = self.create_encrypted_object(
                ObjectType::Version,
                version_data,
                &repo.repo_key,
            )?;
            objects_to_push.push(version_object);
            
            // Create signature object
            let signature = file.get_signature(version.version)?;
            let signature_data = signature.serialize()?;
            let signature_object = self.create_encrypted_object(
                ObjectType::Signature,
                signature_data,
                &repo.repo_key,
            )?;
            objects_to_push.push(signature_object);
        }
        
        // Upload objects
        cloud_provider.push_objects(objects_to_push).await?;
        
        // Update device reference to point to latest version
        let head_version = file.current_version();
        let head_object_id = compute_object_id(ObjectType::Version, &head_version);
        self.update_device_ref(file_id, head_object_id, cloud_provider).await?;
        
        Ok(PushResult::Pushed {
            versions_uploaded: missing_versions.len(),
            bytes_uploaded: objects_to_push.iter().map(|o| o.encrypted_data.len()).sum(),
        })
    }
    
    /// Create encrypted object
    fn create_encrypted_object(
        &self,
        object_type: ObjectType,
        data: Vec<u8>,
        repo_key: &ChaCha20Key,
    ) -> Result<SyncObject> {
        // Generate unique nonce
        let nonce = ChaCha20Nonce::generate();
        
        // Encrypt data
        let cipher = ChaCha20Poly1305::new(repo_key);
        let encrypted_data = cipher.encrypt(&nonce, data.as_slice())?;
        
        // Compute content-based ID
        let object_id = compute_object_id(object_type, &data);
        
        Ok(SyncObject {
            object_id,
            encrypted_data,
            nonce: nonce.as_bytes(),
            auth_tag: encrypted_data[encrypted_data.len()-16..].try_into()?,
        })
    }
}
```

#### Phase 3: Download Remote Changes

```rust
impl SyncEngine {
    /// Download and apply remote changes
    pub async fn pull_changes(
        &mut self,
        file: &mut AionFile,
        cloud_provider: &dyn CloudProvider,
    ) -> Result<PullResult> {
        let file_id = file.file_id();
        let repo = self.get_repository(file_id)?;
        
        // Get remote device references
        let remote_refs = cloud_provider.get_all_refs(file_id).await?;
        
        // Find objects we don't have locally
        let local_objects = self.get_local_object_ids(file);
        let remote_objects = self.collect_remote_objects(&remote_refs, cloud_provider).await?;
        let missing_objects: Vec<_> = remote_objects.iter()
            .filter(|id| !local_objects.contains(id))
            .cloned()
            .collect();
        
        if missing_objects.is_empty() {
            return Ok(PullResult::AlreadyUpToDate);
        }
        
        // Download missing objects
        let encrypted_objects = cloud_provider.get_objects(missing_objects.clone()).await?;
        
        // Decrypt and validate objects
        let mut new_versions = Vec::new();
        let mut new_signatures = Vec::new();
        
        for encrypted_obj in encrypted_objects {
            let decrypted_data = self.decrypt_object(&encrypted_obj, &repo.repo_key)?;
            
            match self.classify_object(&encrypted_obj.object_id, &decrypted_data)? {
                ObjectType::Version => {
                    let version = VersionNode::deserialize(&decrypted_data)?;
                    new_versions.push(version);
                }
                ObjectType::Signature => {
                    let signature = VersionSignature::deserialize(&decrypted_data)?;
                    new_signatures.push(signature);
                }
                ObjectType::AuditEntry => {
                    let audit_entry = AuditEntry::deserialize(&decrypted_data)?;
                    // Handle audit entries if needed
                }
            }
        }
        
        // Apply new versions to local file
        let merge_result = self.merge_remote_versions(file, new_versions, new_signatures)?;
        
        Ok(PullResult::Updated {
            versions_downloaded: merge_result.versions_added,
            conflicts_resolved: merge_result.conflicts,
            bytes_downloaded: encrypted_objects.iter()
                .map(|o| o.encrypted_data.len())
                .sum(),
        })
    }
}
```

#### Phase 4: Conflict Resolution

```rust
impl SyncEngine {
    /// Merge remote versions with local file
    fn merge_remote_versions(
        &self,
        file: &mut AionFile,
        remote_versions: Vec<VersionNode>,
        remote_signatures: Vec<VersionSignature>,
    ) -> Result<MergeResult> {
        let mut conflicts = Vec::new();
        let mut versions_added = 0;
        
        // Build combined version graph
        let mut combined_chain = file.get_version_chain().clone();
        
        // Add remote versions that don't conflict
        for remote_version in remote_versions {
            match combined_chain.add_version(remote_version.clone()) {
                Ok(()) => {
                    versions_added += 1;
                }
                Err(AionError::VersionConflict { .. }) => {
                    // Handle version conflicts
                    let conflict = self.resolve_version_conflict(
                        &combined_chain,
                        &remote_version,
                    )?;
                    conflicts.push(conflict);
                    versions_added += 1;
                }
                Err(e) => return Err(e),
            }
        }
        
        // Update file with merged chain
        file.update_version_chain(combined_chain)?;
        
        // Verify all signatures are valid
        for signature in remote_signatures {
            file.add_signature(signature)?;
        }
        
        Ok(MergeResult {
            versions_added,
            conflicts: conflicts.len(),
        })
    }
    
    /// Resolve conflicts using last-writer-wins with device priority
    fn resolve_version_conflict(
        &self,
        chain: &VersionChain,
        remote_version: &VersionNode,
    ) -> Result<ConflictResolution> {
        // Find local version with same version number
        let local_version = chain.get_version(remote_version.version)
            .ok_or(AionError::VersionNotFound { 
                version: remote_version.version 
            })?;
        
        // Compare timestamps (last writer wins)
        let winner = if remote_version.timestamp > local_version.timestamp {
            ConflictWinner::Remote(remote_version.clone())
        } else if remote_version.timestamp < local_version.timestamp {
            ConflictWinner::Local(local_version.clone())
        } else {
            // Same timestamp - use device ID as tiebreaker
            if remote_version.author > local_version.author {
                ConflictWinner::Remote(remote_version.clone())
            } else {
                ConflictWinner::Local(local_version.clone())
            }
        };
        
        Ok(ConflictResolution {
            version_number: remote_version.version,
            winner,
            resolution_strategy: ResolutionStrategy::LastWriterWins,
        })
    }
}
```

### Cloud Provider Interface

```rust
/// Abstraction over cloud storage providers
#[async_trait]
pub trait CloudProvider: Send + Sync {
    /// Upload encrypted manifest
    async fn put_manifest(
        &self,
        file_id: FileId,
        encrypted_manifest: Vec<u8>,
    ) -> Result<()>;
    
    /// Download encrypted manifest
    async fn get_manifest(&self, file_id: FileId) -> Result<Vec<u8>>;
    
    /// Upload multiple objects
    async fn push_objects(&self, objects: Vec<SyncObject>) -> Result<()>;
    
    /// Download specific objects
    async fn get_objects(&self, object_ids: Vec<ObjectId>) -> Result<Vec<SyncObject>>;
    
    /// List all object IDs
    async fn list_objects(&self, file_id: FileId) -> Result<Vec<ObjectId>>;
    
    /// Update device reference
    async fn update_ref(
        &self,
        file_id: FileId,
        device_id: DeviceId,
        head_object: ObjectId,
        signature: [u8; 64],
    ) -> Result<()>;
    
    /// Get all device references
    async fn get_all_refs(&self, file_id: FileId) -> Result<HashMap<DeviceId, ObjectId>>;
    
    /// Check if file sync repository exists
    async fn exists(&self, file_id: FileId) -> Result<bool>;
}

/// S3-compatible cloud storage implementation
pub struct S3CloudProvider {
    client: S3Client,
    bucket: String,
    prefix: String,
}

#[async_trait]
impl CloudProvider for S3CloudProvider {
    async fn put_manifest(
        &self,
        file_id: FileId,
        encrypted_manifest: Vec<u8>,
    ) -> Result<()> {
        let key = format!("{}/sync-repo-{}/manifest.json.enc", 
                         self.prefix, file_id);
        
        self.client.put_object(PutObjectRequest {
            bucket: self.bucket.clone(),
            key,
            body: Some(encrypted_manifest.into()),
            ..Default::default()
        }).await?;
        
        Ok(())
    }
    
    async fn get_manifest(&self, file_id: FileId) -> Result<Vec<u8>> {
        let key = format!("{}/sync-repo-{}/manifest.json.enc", 
                         self.prefix, file_id);
        
        let response = self.client.get_object(GetObjectRequest {
            bucket: self.bucket.clone(),
            key,
            ..Default::default()
        }).await?;
        
        let body = response.body.ok_or(CloudError::EmptyResponse)?;
        let bytes = body.collect().await?.into_bytes();
        
        Ok(bytes.to_vec())
    }
    
    // ... implement remaining methods
}
```

### Security Considerations

#### End-to-End Encryption

```rust
/// All data is encrypted before leaving the device
pub fn encrypt_for_cloud(
    data: &[u8],
    repo_key: &ChaCha20Key,
) -> Result<(Vec<u8>, [u8; 12])> {
    let nonce = ChaCha20Nonce::generate();
    let cipher = ChaCha20Poly1305::new(repo_key);
    
    let encrypted = cipher.encrypt(&nonce, data)?;
    
    Ok((encrypted, *nonce.as_bytes()))
}

/// Repository key is derived from file ID and user master key
pub fn derive_repo_key(
    file_id: FileId,
    user_master_key: &[u8; 32],
) -> ChaCha20Key {
    let hkdf = Hkdf::<Sha256>::new(None, user_master_key);
    let mut repo_key = [0u8; 32];
    
    hkdf.expand(&file_id.to_le_bytes(), &mut repo_key)
        .expect("HKDF expand never fails");
    
    ChaCha20Key::from_bytes(repo_key)
}
```

#### Device Authentication

```rust
/// Each device signs its sync operations
pub fn sign_sync_operation(
    operation: &SyncMessage,
    device_private_key: &Ed25519PrivateKey,
) -> Result<[u8; 64]> {
    let message = operation.serialize()?;
    let signature = device_private_key.sign(&message);
    Ok(signature.to_bytes())
}

/// Verify sync operation signature
pub fn verify_sync_operation(
    operation: &SyncMessage,
    signature: &[u8; 64],
    device_public_key: &Ed25519PublicKey,
) -> Result<bool> {
    let message = operation.serialize()?;
    let signature_obj = Ed25519Signature::from_bytes(signature)?;
    
    Ok(device_public_key.verify(&message, &signature_obj).is_ok())
}
```

## Performance Characteristics

### Bandwidth Efficiency

- **Incremental Sync:** Only new versions transferred
- **Content Deduplication:** Identical objects shared across files
- **Compression:** Objects compressed before encryption
- **Parallel Transfer:** Multiple objects uploaded/downloaded concurrently

### Storage Efficiency

- **Content Addressing:** Eliminates duplicate data
- **Efficient Encoding:** Binary serialization minimizes overhead  
- **Garbage Collection:** Unreferenced objects can be safely deleted
- **Compression:** Up to 70% size reduction for structured data

### Latency Optimization

- **Background Sync:** Runs asynchronously, doesn't block local operations
- **Smart Scheduling:** Syncs during low activity periods
- **Conflict Caching:** Pre-computed merge resolutions
- **Partial Downloads:** Stream processing of large files

## Implementation Plan

### Phase 1: Core Protocol (Week 1-2)
- Define sync data structures and protocol messages
- Implement basic encryption/decryption
- Create cloud provider interface

### Phase 2: Sync Engine (Week 3-4)
- Implement push/pull operations
- Add conflict resolution
- Create device management

### Phase 3: Cloud Providers (Week 5-6)  
- S3-compatible implementation
- Google Drive adapter
- Dropbox integration

### Phase 4: CLI Integration (Week 7-8)
- Add sync commands to AION CLI
- Configuration management
- Status reporting and diagnostics

## Testing Strategy

### Unit Tests
- Protocol message serialization
- Encryption/decryption correctness
- Conflict resolution algorithms
- Cloud provider mocks

### Integration Tests
- End-to-end sync scenarios
- Multi-device simulation
- Network failure handling
- Concurrent access patterns

### Security Tests
- Encryption key derivation
- Device authentication
- Man-in-the-middle resistance
- Cloud provider isolation

## Open Questions

1. Should we implement real-time notifications for sync events?
2. How to handle very large files (>1GB) efficiently?
3. Should sync support partial file synchronization?
4. How to implement sync access control (shared files)?

## References

- [Git Protocol Documentation](https://git-scm.com/book/en/v2/Git-Internals-Transfer-Protocols)
- [Dropbox Sync Protocol](https://dropbox.tech/infrastructure/rewriting-the-heart-of-our-sync-engine)
- [IPFS Content Addressing](https://docs.ipfs.io/concepts/content-addressing/)
- [Signal Protocol for E2E Encryption](https://signal.org/docs/)
- [Conflict-Free Replicated Data Types](https://hal.inria.fr/hal-00932836/document)

## Appendix

### Sync Flow Diagram

```
Device A                Cloud Storage              Device B
   |                         |                        |
   |--- Push Changes ------->|                        |
   |                         |<--- Pull Changes -----|
   |                         |                        |
   |<-- Conflict Resolution->|<-- Conflict Resolution-|
   |                         |                        |
   |--- Update Ref --------->|                        |
   |                         |--- Update Ref -------->|
   |                         |                        |
```

### Configuration Example

```toml
# ~/.aion/sync.toml
[sync]
enabled = true
provider = "s3"
background_interval = 300  # 5 minutes

[providers.s3]
bucket = "my-aion-sync"
region = "us-west-2"
access_key_id = "${AWS_ACCESS_KEY_ID}"
secret_access_key = "${AWS_SECRET_ACCESS_KEY}"

[providers.gdrive] 
client_id = "your-oauth-client-id"
client_secret = "${GDRIVE_CLIENT_SECRET}"
```

### CLI Commands

```bash
# Initialize sync for a file
$ aion sync init myfile.aion --provider s3

# Manual sync
$ aion sync push myfile.aion
$ aion sync pull myfile.aion

# Sync status
$ aion sync status myfile.aion

# Resolve conflicts interactively  
$ aion sync resolve myfile.aion

# Add device to sync
$ aion sync add-device --device-id laptop-work
```
