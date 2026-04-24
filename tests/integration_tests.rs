//! Integration tests for AION v2
//!
//! These tests verify end-to-end workflows across multiple modules.

#![allow(clippy::expect_used)] // Test code needs `.expect()` for clarity
#![allow(clippy::indexing_slicing)] // Test code can safely index known data
#![allow(clippy::missing_const_for_fn)] // Test helpers don't need to be const
#![allow(clippy::unwrap_used)] // Test assertions can use unwrap
#![allow(clippy::unwrap_in_result)] // Test code can unwrap

use aion_context::crypto::SigningKey;
use aion_context::operations::{
    commit_version, init_file, show_current_rules, show_file_info, show_version_history,
    verify_file, CommitOptions, InitOptions,
};
use aion_context::types::AuthorId;
use std::fs;
use tempfile::TempDir;

/// Test helper to create a temporary directory
fn setup_test_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp dir")
}

/// Test helper to create a signing key
fn create_test_key() -> SigningKey {
    SigningKey::generate()
}

/// Test helper to create init options
fn create_init_options<'a>(
    author_id: u64,
    key: &'a SigningKey,
    message: &'a str,
) -> InitOptions<'a> {
    InitOptions {
        author_id: AuthorId::new(author_id),
        signing_key: key,
        message,
        timestamp: None,
    }
}

/// Test helper to create commit options
fn create_commit_options<'a>(
    author_id: u64,
    key: &'a SigningKey,
    message: &'a str,
) -> CommitOptions<'a> {
    CommitOptions {
        author_id: AuthorId::new(author_id),
        signing_key: key,
        message,
        timestamp: None,
    }
}

// ============================================================================
// Full Workflow Tests
// ============================================================================

#[test]
fn test_complete_workflow_init_commit_verify() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("test.aion");
    let signing_key = create_test_key();

    // Step 1: Initialize file
    let rules_v1 = b"fraud_threshold: 1000\nrisk_level: medium";
    let init_options = create_init_options(5001, &signing_key, "Initial rules");

    let init_result =
        init_file(&file_path, rules_v1, &init_options).expect("Failed to initialize file");

    assert_eq!(init_result.version.as_u64(), 1);
    assert!(file_path.exists());

    // Step 2: Verify initial file
    let verify_result = verify_file(&file_path).expect("Failed to verify file");
    assert!(verify_result.is_valid);
    assert_eq!(verify_result.version_count, 1);
    assert!(verify_result.structure_valid);
    assert!(verify_result.integrity_hash_valid);
    assert!(verify_result.hash_chain_valid);
    assert!(verify_result.signatures_valid);

    // Step 3: Commit new version
    let rules_v2 = b"fraud_threshold: 500\nrisk_level: high";
    let commit_options = create_commit_options(5001, &signing_key, "Updated thresholds");

    let commit_result =
        commit_version(&file_path, rules_v2, &commit_options).expect("Failed to commit version");

    assert_eq!(commit_result.version.as_u64(), 2);

    // Step 4: Verify updated file
    let verify_result = verify_file(&file_path).expect("Failed to verify file");
    assert!(verify_result.is_valid);
    assert_eq!(verify_result.version_count, 2);

    // Step 5: Show version history
    let history = show_version_history(&file_path).expect("Failed to get history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].version_number, 1);
    assert_eq!(history[0].message, "Initial rules");
    assert_eq!(history[1].version_number, 2);
    assert_eq!(history[1].message, "Updated thresholds");

    // Step 6: Show current rules
    let current_rules = show_current_rules(&file_path).expect("Failed to get current rules");
    assert_eq!(current_rules, rules_v2);
}

#[test]
fn test_multiple_commits_workflow() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("multi.aion");
    let signing_key = create_test_key();

    // Initialize
    let init_options = create_init_options(6001, &signing_key, "v1");
    init_file(&file_path, b"version 1", &init_options).expect("Init failed");

    // Commit multiple versions
    for i in 2..=5 {
        let rules = format!("version {i}").into_bytes();
        let message = format!("v{i}");
        let commit_options = create_commit_options(6001, &signing_key, &message);

        let result = commit_version(&file_path, &rules, &commit_options).expect("Commit failed");
        assert_eq!(result.version.as_u64(), i);
    }

    // Verify final state
    let verify_result = verify_file(&file_path).expect("Verify failed");
    assert!(verify_result.is_valid);
    assert_eq!(verify_result.version_count, 5);

    // Check history
    let history = show_version_history(&file_path).expect("History failed");
    assert_eq!(history.len(), 5);
    for (idx, entry) in history.iter().enumerate() {
        assert_eq!(entry.version_number, (idx + 1) as u64);
    }
}

#[test]
fn test_multiple_authors_workflow() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("multi_author.aion");

    // Two different authors with different keys
    let key1 = create_test_key();
    let key2 = create_test_key();

    // Author 1 initializes
    let init_options = create_init_options(7001, &key1, "Author 1 init");
    init_file(&file_path, b"initial", &init_options).expect("Init failed");

    // Author 2 commits
    let commit_options = create_commit_options(7002, &key2, "Author 2 commit");
    commit_version(&file_path, b"updated by author 2", &commit_options).expect("Commit failed");

    // Author 1 commits again
    let commit_options = create_commit_options(7001, &key1, "Author 1 commit");
    commit_version(&file_path, b"updated by author 1 again", &commit_options)
        .expect("Commit failed");

    // Verify
    let verify_result = verify_file(&file_path).expect("Verify failed");
    assert!(verify_result.is_valid);
    assert_eq!(verify_result.version_count, 3);

    // Check author IDs in history
    let history = show_version_history(&file_path).expect("History failed");
    assert_eq!(history[0].author_id, 7001);
    assert_eq!(history[1].author_id, 7002);
    assert_eq!(history[2].author_id, 7001);
}

// ============================================================================
// Error Path Tests
// ============================================================================

#[test]
fn test_init_file_already_exists() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("exists.aion");
    let signing_key = create_test_key();

    // Create file first
    let init_options = create_init_options(8001, &signing_key, "First");
    init_file(&file_path, b"data", &init_options).expect("Init failed");

    // Try to create again - should fail
    let result = init_file(&file_path, b"data2", &init_options);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already exists"));
}

#[test]
fn test_commit_to_nonexistent_file() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("nonexistent.aion");
    let signing_key = create_test_key();

    let commit_options = create_commit_options(8002, &signing_key, "Commit");
    let result = commit_version(&file_path, b"data", &commit_options);

    assert!(result.is_err());
}

#[test]
fn test_verify_nonexistent_file() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("missing.aion");

    let result = verify_file(&file_path);
    assert!(result.is_err());
}

#[test]
fn test_show_operations_on_nonexistent_file() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("missing.aion");

    assert!(show_current_rules(&file_path).is_err());
    assert!(show_version_history(&file_path).is_err());
    assert!(show_file_info(&file_path).is_err());
}

// ============================================================================
// File Corruption Tests
// ============================================================================

#[test]
fn test_verify_detects_truncated_file() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("truncated.aion");
    let signing_key = create_test_key();

    // Create valid file
    let init_options = create_init_options(9001, &signing_key, "Original");
    init_file(&file_path, b"data", &init_options).expect("Init failed");

    // Truncate the file
    let original_data = fs::read(&file_path).expect("Read failed");
    let truncated = &original_data[..original_data.len() / 2];
    fs::write(&file_path, truncated).expect("Write failed");

    // Verify should detect corruption
    let result = verify_file(&file_path);
    assert!(result.is_err() || !result.unwrap().is_valid);
}

#[test]
fn test_verify_detects_modified_content() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("modified.aion");
    let signing_key = create_test_key();

    // Create valid file
    let init_options = create_init_options(9002, &signing_key, "Original");
    init_file(&file_path, b"data", &init_options).expect("Init failed");

    // Modify a byte in the middle of the file
    let mut data = fs::read(&file_path).expect("Read failed");
    if data.len() > 100 {
        data[100] ^= 0xFF; // Flip bits
        fs::write(&file_path, data).expect("Write failed");

        // Verify should detect corruption
        let result = verify_file(&file_path).expect("Verify failed");
        assert!(!result.is_valid);
    }
}

// ============================================================================
// Boundary Tests
// ============================================================================

#[test]
fn test_empty_rules() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("empty.aion");
    let signing_key = create_test_key();

    let init_options = create_init_options(10001, &signing_key, "Empty rules");
    let result = init_file(&file_path, b"", &init_options);

    assert!(result.is_ok());
    let verify_result = verify_file(&file_path).expect("Verify failed");
    assert!(verify_result.is_valid);
}

#[test]
fn test_large_rules() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("large.aion");
    let signing_key = create_test_key();

    // Create 1MB of rules data
    let large_rules = vec![b'A'; 1024 * 1024];

    let init_options = create_init_options(10002, &signing_key, "Large rules");
    let result = init_file(&file_path, &large_rules, &init_options);

    assert!(result.is_ok());
    let verify_result = verify_file(&file_path).expect("Verify failed");
    assert!(verify_result.is_valid);

    // Verify we can read it back
    let retrieved_rules = show_current_rules(&file_path).expect("Show rules failed");
    assert_eq!(retrieved_rules.len(), large_rules.len());
}

#[test]
fn test_long_message() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("long_msg.aion");
    let signing_key = create_test_key();

    let long_message = "A".repeat(1000);
    let init_options = InitOptions {
        author_id: AuthorId::new(10003),
        signing_key: &signing_key,
        message: &long_message,
        timestamp: None,
    };

    let result = init_file(&file_path, b"data", &init_options);
    assert!(result.is_ok());

    let history = show_version_history(&file_path).expect("History failed");
    assert_eq!(history[0].message, long_message);
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

#[test]
fn test_multiple_readers() {
    use std::sync::Arc;
    use std::thread;

    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("concurrent.aion");
    let signing_key = create_test_key();

    // Create file
    let init_options = create_init_options(11001, &signing_key, "Concurrent test");
    init_file(&file_path, b"shared data", &init_options).expect("Init failed");

    // Share path across threads
    let file_path = Arc::new(file_path);

    // Spawn multiple readers
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let path = Arc::clone(&file_path);
            thread::spawn(move || {
                let result = verify_file(&path).expect("Verify failed");
                assert!(result.is_valid);

                let rules = show_current_rules(&path).expect("Show rules failed");
                assert_eq!(rules, b"shared data");
            })
        })
        .collect();

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn test_file_info_completeness() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("info.aion");
    let signing_key = create_test_key();

    // Create file with multiple versions
    let init_options = create_init_options(12001, &signing_key, "v1");
    init_file(&file_path, b"data1", &init_options).expect("Init failed");

    let commit_options = create_commit_options(12001, &signing_key, "v2");
    commit_version(&file_path, b"data2", &commit_options).expect("Commit failed");

    // Get file info
    let info = show_file_info(&file_path).expect("Show info failed");

    assert_eq!(info.version_count, 2);
    assert_eq!(info.current_version, 2);
    assert_eq!(info.versions.len(), 2);
    assert_eq!(info.signatures.len(), 2);

    // Verify signatures are all valid
    for sig in &info.signatures {
        assert!(sig.verified, "Signature should be valid");
    }
}

// ============================================================================
// Advanced Error Path Tests
// ============================================================================

#[test]
fn test_verify_detects_corrupted_header_magic() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("bad_magic.aion");
    let signing_key = create_test_key();

    // Create valid file
    let init_options = create_init_options(9003, &signing_key, "Original");
    init_file(&file_path, b"data", &init_options).expect("Init failed");

    // Corrupt magic bytes (first 4 bytes)
    let mut data = fs::read(&file_path).expect("Read failed");
    data[0] = 0x00;
    data[1] = 0x00;
    data[2] = 0x00;
    data[3] = 0x00;
    fs::write(&file_path, data).expect("Write failed");

    // Verify should fail
    let result = verify_file(&file_path);
    assert!(result.is_err(), "Should detect corrupted magic");
}

#[test]
fn test_verify_detects_corrupted_signature() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("bad_sig.aion");
    let signing_key = create_test_key();

    // Create valid file
    let init_options = create_init_options(9004, &signing_key, "Original");
    init_file(&file_path, b"data", &init_options).expect("Init failed");

    // Corrupt signature section (near the end of file)
    let mut data = fs::read(&file_path).expect("Read failed");
    if data.len() > 100 {
        // Corrupt bytes near the end where signature likely is
        let sig_offset = data.len() - 80;
        data[sig_offset] ^= 0xFF;
        data[sig_offset + 1] ^= 0xFF;
        fs::write(&file_path, data).expect("Write failed");

        let result = verify_file(&file_path).expect("Verify should return result");
        assert!(
            !result.is_valid || !result.signatures_valid,
            "Should detect corrupted signature"
        );
    }
}

#[test]
fn test_commit_preserves_previous_versions() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("preserve.aion");
    let signing_key = create_test_key();

    // Initialize with first rules
    let init_options = create_init_options(9005, &signing_key, "v1");
    init_file(&file_path, b"rules v1", &init_options).expect("Init failed");

    // Commit second version
    let commit_options = create_commit_options(9005, &signing_key, "v2");
    commit_version(&file_path, b"rules v2", &commit_options).expect("Commit failed");

    // Current rules should be v2
    let current = show_current_rules(&file_path).expect("Show rules failed");
    assert_eq!(current, b"rules v2");

    // History should contain both versions
    let history = show_version_history(&file_path).expect("History failed");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].message, "v1");
    assert_eq!(history[1].message, "v2");
}

#[test]
fn test_binary_rules_content() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("binary.aion");
    let signing_key = create_test_key();

    // Binary data with all byte values
    let binary_rules: Vec<u8> = (0..=255).collect();

    let init_options = create_init_options(9006, &signing_key, "Binary rules");
    init_file(&file_path, &binary_rules, &init_options).expect("Init failed");

    // Verify and read back
    let verify_result = verify_file(&file_path).expect("Verify failed");
    assert!(verify_result.is_valid);

    let retrieved = show_current_rules(&file_path).expect("Show rules failed");
    assert_eq!(retrieved, binary_rules);
}

#[test]
fn test_unicode_message_content() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("unicode.aion");
    let signing_key = create_test_key();

    // Unicode message with various scripts
    let unicode_message = "Updated rules: 日本語 🎉 مرحبا Привет";

    let init_options = InitOptions {
        author_id: AuthorId::new(9007),
        signing_key: &signing_key,
        message: unicode_message,
        timestamp: None,
    };

    init_file(&file_path, b"rules", &init_options).expect("Init failed");

    let history = show_version_history(&file_path).expect("History failed");
    assert_eq!(history[0].message, unicode_message);
}

#[test]
fn test_rapid_sequential_commits() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("rapid.aion");
    let signing_key = create_test_key();

    // Initialize
    let init_options = create_init_options(9008, &signing_key, "v1");
    init_file(&file_path, b"v1", &init_options).expect("Init failed");

    // Rapid sequential commits
    for i in 2..=10 {
        let msg = format!("v{}", i);
        let rules = format!("rules version {}", i).into_bytes();
        let commit_options = create_commit_options(9008, &signing_key, &msg);
        commit_version(&file_path, &rules, &commit_options).expect("Commit failed");
    }

    // Verify final state
    let verify_result = verify_file(&file_path).expect("Verify failed");
    assert!(verify_result.is_valid);
    assert_eq!(verify_result.version_count, 10);
}

#[test]
fn test_many_authors_sequential() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("many_authors.aion");

    // Create 5 different authors with different keys
    let keys: Vec<_> = (0..5).map(|_| create_test_key()).collect();
    let author_ids: Vec<u64> = (9010..9015).collect();

    // First author initializes
    let init_options = create_init_options(author_ids[0], &keys[0], "Author 0 init");
    init_file(&file_path, b"initial", &init_options).expect("Init failed");

    // Each author commits in sequence
    for i in 1..5 {
        let msg = format!("Author {} commit", i);
        let commit_options = create_commit_options(author_ids[i], &keys[i], &msg);
        let rules = format!("rules from author {}", i).into_bytes();
        commit_version(&file_path, &rules, &commit_options).expect("Commit failed");
    }

    // Verify
    let verify_result = verify_file(&file_path).expect("Verify failed");
    assert!(verify_result.is_valid);
    assert_eq!(verify_result.version_count, 5);

    // Check history has all authors
    let history = show_version_history(&file_path).expect("History failed");
    for (i, entry) in history.iter().enumerate() {
        assert_eq!(entry.author_id, author_ids[i]);
    }
}

#[test]
fn test_verify_after_append_operations() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("append.aion");
    let signing_key = create_test_key();

    // Init
    let init_options = create_init_options(9020, &signing_key, "v1");
    init_file(&file_path, b"v1", &init_options).expect("Init failed");

    // Append garbage to end of file
    let mut data = fs::read(&file_path).expect("Read failed");
    data.extend_from_slice(b"GARBAGE_DATA_APPENDED");
    fs::write(&file_path, data).expect("Write failed");

    // Verification should fail due to integrity check
    let result = verify_file(&file_path).expect("Verify should return result");
    assert!(
        !result.is_valid || !result.integrity_hash_valid,
        "Should detect appended data"
    );
}

#[test]
fn test_zero_byte_rules() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("zero_byte.aion");
    let signing_key = create_test_key();

    // Rules with null bytes embedded
    let rules_with_nulls = b"rule1\x00value1\x00rule2\x00value2";

    let init_options = create_init_options(9021, &signing_key, "Null bytes");
    init_file(&file_path, rules_with_nulls, &init_options).expect("Init failed");

    let verify_result = verify_file(&file_path).expect("Verify failed");
    assert!(verify_result.is_valid);

    let retrieved = show_current_rules(&file_path).expect("Show rules failed");
    assert_eq!(retrieved, rules_with_nulls);
}

// ============================================================================
// Temporal Ordering Validation Tests (Issue #36)
// ============================================================================

use aion_context::operations::TemporalWarning;

#[test]
fn test_temporal_validation_monotonic_timestamps() {
    // Normal case: monotonically increasing timestamps should produce no warnings
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("monotonic.aion");
    let signing_key = create_test_key();

    // Create file with version 1
    let init_options = InitOptions {
        author_id: AuthorId::new(9030),
        signing_key: &signing_key,
        message: "v1",
        timestamp: Some(1700000000_000_000_000), // Fixed timestamp
    };
    init_file(&file_path, b"v1", &init_options).expect("Init failed");

    // Add version 2 with later timestamp
    let commit_options = CommitOptions {
        author_id: AuthorId::new(9030),
        signing_key: &signing_key,
        message: "v2",
        timestamp: Some(1700000001_000_000_000), // 1 second later
    };
    commit_version(&file_path, b"v2", &commit_options).expect("Commit failed");

    // Add version 3 with later timestamp
    let commit_options = CommitOptions {
        author_id: AuthorId::new(9030),
        signing_key: &signing_key,
        message: "v3",
        timestamp: Some(1700000002_000_000_000), // 2 seconds later
    };
    commit_version(&file_path, b"v3", &commit_options).expect("Commit failed");

    // Verify - should have NO temporal warnings
    let result = verify_file(&file_path).expect("Verify failed");
    assert!(result.is_valid, "File should be valid");
    assert!(
        result.temporal_warnings.is_empty(),
        "Monotonic timestamps should produce no warnings, got: {:?}",
        result.temporal_warnings
    );
}

#[test]
fn test_temporal_validation_non_monotonic_timestamps() {
    // Backdated version: should produce NonMonotonicTimestamp warning
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("non_monotonic.aion");
    let signing_key = create_test_key();

    // Create file at time T
    let init_options = InitOptions {
        author_id: AuthorId::new(9031),
        signing_key: &signing_key,
        message: "v1",
        timestamp: Some(1700000100_000_000_000), // T = 100
    };
    init_file(&file_path, b"v1", &init_options).expect("Init failed");

    // Add version 2 at time T - 50s (backdated by more than 5 min tolerance)
    let commit_options = CommitOptions {
        author_id: AuthorId::new(9031),
        signing_key: &signing_key,
        message: "v2 backdated",
        timestamp: Some(1699999600_000_000_000), // T - 500 seconds (significantly backdated)
    };
    commit_version(&file_path, b"v2", &commit_options).expect("Commit failed");

    // Verify - should still be valid but have temporal warning
    let result = verify_file(&file_path).expect("Verify failed");
    assert!(
        result.is_valid,
        "File should be valid (temporal warnings don't affect validity)"
    );
    assert!(
        !result.temporal_warnings.is_empty(),
        "Should have temporal warnings for backdated version"
    );

    // Check it's the right kind of warning
    let has_non_monotonic = result
        .temporal_warnings
        .iter()
        .any(|w| matches!(w, TemporalWarning::NonMonotonicTimestamp { version: 2, .. }));
    assert!(
        has_non_monotonic,
        "Should have NonMonotonicTimestamp warning for version 2"
    );
}

#[test]
fn test_temporal_validation_clock_skew() {
    // Small time difference (within tolerance) should produce ClockSkewDetected
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("clock_skew.aion");
    let signing_key = create_test_key();

    // Create file at time T
    let init_options = InitOptions {
        author_id: AuthorId::new(9032),
        signing_key: &signing_key,
        message: "v1",
        timestamp: Some(1700000010_000_000_000), // T = 10s
    };
    init_file(&file_path, b"v1", &init_options).expect("Init failed");

    // Add version 2 at time T - 2s (within 5 minute tolerance)
    let commit_options = CommitOptions {
        author_id: AuthorId::new(9032),
        signing_key: &signing_key,
        message: "v2 slight skew",
        timestamp: Some(1700000008_000_000_000), // T - 2 seconds (minor skew)
    };
    commit_version(&file_path, b"v2", &commit_options).expect("Commit failed");

    // Verify - should be valid with clock skew warning
    let result = verify_file(&file_path).expect("Verify failed");
    assert!(result.is_valid);

    let has_clock_skew = result
        .temporal_warnings
        .iter()
        .any(|w| matches!(w, TemporalWarning::ClockSkewDetected { version: 2, .. }));
    assert!(
        has_clock_skew,
        "Should have ClockSkewDetected warning for minor time difference"
    );
}

#[test]
fn test_temporal_validation_future_timestamp() {
    // Future timestamp: should produce FutureTimestamp warning
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("future.aion");
    let signing_key = create_test_key();

    // Create file with a timestamp far in the future
    // Year 2100: way beyond any reasonable tolerance
    let init_options = InitOptions {
        author_id: AuthorId::new(9033),
        signing_key: &signing_key,
        message: "Future version",
        timestamp: Some(4102444800_000_000_000), // Year 2100
    };
    init_file(&file_path, b"future rules", &init_options).expect("Init failed");

    // Verify - should be valid but with future timestamp warning
    let result = verify_file(&file_path).expect("Verify failed");
    assert!(
        result.is_valid,
        "File should be valid (future timestamps don't affect validity)"
    );

    let has_future_warning = result
        .temporal_warnings
        .iter()
        .any(|w| matches!(w, TemporalWarning::FutureTimestamp { version: 1, .. }));
    assert!(
        has_future_warning,
        "Should have FutureTimestamp warning for year 2100 timestamp"
    );
}

#[test]
fn test_temporal_validation_does_not_affect_validity() {
    // Critical test: temporal warnings must NOT affect is_valid
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("validity_check.aion");
    let signing_key = create_test_key();

    // Create file with multiple temporal issues
    let init_options = InitOptions {
        author_id: AuthorId::new(9034),
        signing_key: &signing_key,
        message: "v1",
        timestamp: Some(4102444800_000_000_000), // Future timestamp (year 2100)
    };
    init_file(&file_path, b"v1", &init_options).expect("Init failed");

    // Add backdated version
    let commit_options = CommitOptions {
        author_id: AuthorId::new(9034),
        signing_key: &signing_key,
        message: "v2 backdated",
        timestamp: Some(1700000000_000_000_000), // Normal past time
    };
    commit_version(&file_path, b"v2", &commit_options).expect("Commit failed");

    // Verify - MUST be valid despite temporal warnings
    let result = verify_file(&file_path).expect("Verify failed");

    assert!(
        !result.temporal_warnings.is_empty(),
        "Should have temporal warnings"
    );
    assert!(
        result.is_valid,
        "is_valid MUST be true - temporal warnings are informational only"
    );
    assert!(result.structure_valid);
    assert!(result.hash_chain_valid);
    assert!(result.signatures_valid);
}

// ============================================================================
// Compliance Reporting Tests (Issue #33)
// ============================================================================

use aion_context::compliance::{generate_compliance_report, ComplianceFramework, ReportFormat};
use aion_context::export::{export_file, import_json, import_yaml, ExportFormat};

#[test]
fn test_compliance_report_sox() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("sox_test.aion");
    let signing_key = create_test_key();

    // Create file
    let init_options = create_init_options(9040, &signing_key, "Initial policy");
    init_file(&file_path, b"SOX compliance rules", &init_options).expect("Init failed");

    // Generate SOX report
    let report =
        generate_compliance_report(&file_path, ComplianceFramework::Sox, ReportFormat::Markdown)
            .expect("Report generation failed");

    assert!(report.contains("SOX Compliance Report"));
    assert!(report.contains("Internal Control Assessment"));
    assert!(report.contains("Change Management Log"));
}

#[test]
fn test_compliance_report_hipaa() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("hipaa_test.aion");
    let signing_key = create_test_key();

    let init_options = create_init_options(9041, &signing_key, "PHI handling rules");
    init_file(&file_path, b"HIPAA rules content", &init_options).expect("Init failed");

    let report =
        generate_compliance_report(&file_path, ComplianceFramework::Hipaa, ReportFormat::Text)
            .expect("Report generation failed");

    assert!(report.contains("HIPAA"));
    assert!(report.contains("164.312")); // HIPAA section reference
    assert!(report.contains("Audit Controls"));
}

#[test]
fn test_compliance_report_gdpr() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("gdpr_test.aion");
    let signing_key = create_test_key();

    let init_options = create_init_options(9042, &signing_key, "Data processing rules");
    init_file(&file_path, b"GDPR processing rules", &init_options).expect("Init failed");

    let report = generate_compliance_report(
        &file_path,
        ComplianceFramework::Gdpr,
        ReportFormat::Markdown,
    )
    .expect("Report generation failed");

    assert!(report.contains("GDPR"));
    assert!(report.contains("Article 30")); // GDPR article reference
    assert!(report.contains("Record of Processing Activities"));
}

#[test]
fn test_compliance_report_json_format() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("json_test.aion");
    let signing_key = create_test_key();

    let init_options = create_init_options(9043, &signing_key, "JSON test");
    init_file(&file_path, b"rules", &init_options).expect("Init failed");

    let report =
        generate_compliance_report(&file_path, ComplianceFramework::Generic, ReportFormat::Json)
            .expect("Report generation failed");

    // Should be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&report).expect("Invalid JSON");
    assert!(parsed.get("title").is_some());
    assert!(parsed.get("verification").is_some());
    assert!(parsed.get("version_history").is_some());
}

#[test]
fn test_compliance_report_with_multiple_versions() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("multi_version.aion");
    let signing_key = create_test_key();

    // Create with initial version
    let init_options = create_init_options(9044, &signing_key, "v1");
    init_file(&file_path, b"v1 rules", &init_options).expect("Init failed");

    // Add more versions
    for i in 2..=5 {
        let message = format!("v{i}");
        let commit_options = create_commit_options(9044, &signing_key, &message);
        let rules = format!("v{i} rules");
        commit_version(&file_path, rules.as_bytes(), &commit_options).expect("Commit failed");
    }

    let report =
        generate_compliance_report(&file_path, ComplianceFramework::Sox, ReportFormat::Markdown)
            .expect("Report generation failed");

    // Should contain all versions
    assert!(report.contains("v1"));
    assert!(report.contains("v5"));
    assert!(report.contains("✅ VALID")); // Verification passed
}

// ============================================================================
// Export/Import Tests (Issue #31)
// ============================================================================

#[test]
fn test_export_json() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("export_json.aion");
    let signing_key = create_test_key();

    let init_options = create_init_options(9050, &signing_key, "Export test");
    init_file(&file_path, b"test rules", &init_options).expect("Init failed");

    let json = export_file(&file_path, ExportFormat::Json).expect("Export failed");

    // Verify JSON structure
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON");
    assert!(parsed.get("export_version").is_some());
    assert!(parsed.get("file_info").is_some());
    assert!(parsed.get("versions").is_some());
    assert!(parsed.get("signatures").is_some());
}

#[test]
fn test_export_yaml() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("export_yaml.aion");
    let signing_key = create_test_key();

    let init_options = create_init_options(9051, &signing_key, "YAML export");
    init_file(&file_path, b"yaml rules", &init_options).expect("Init failed");

    let yaml = export_file(&file_path, ExportFormat::Yaml).expect("Export failed");

    assert!(yaml.contains("export_version"));
    assert!(yaml.contains("file_info"));
    assert!(yaml.contains("versions"));
}

#[test]
fn test_export_csv() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("export_csv.aion");
    let signing_key = create_test_key();

    let init_options = create_init_options(9052, &signing_key, "CSV export");
    init_file(&file_path, b"csv rules", &init_options).expect("Init failed");

    // Add another version
    let commit_options = create_commit_options(9052, &signing_key, "Version 2");
    commit_version(&file_path, b"v2 rules", &commit_options).expect("Commit failed");

    let csv = export_file(&file_path, ExportFormat::Csv).expect("Export failed");

    // Check CSV structure
    let lines: Vec<&str> = csv.lines().collect();
    assert!(lines[0].contains("version,author_id,timestamp")); // Header
    assert_eq!(lines.len(), 3); // Header + 2 versions
}

#[test]
fn test_import_json_roundtrip() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("roundtrip.aion");
    let signing_key = create_test_key();

    let init_options = create_init_options(9053, &signing_key, "Roundtrip test");
    init_file(&file_path, b"roundtrip rules", &init_options).expect("Init failed");

    // Export to JSON
    let json = export_file(&file_path, ExportFormat::Json).expect("Export failed");

    // Import back
    let imported = import_json(&json).expect("Import failed");

    assert_eq!(imported.export_version, "1.0");
    assert_eq!(imported.versions.len(), 1);
    assert_eq!(imported.versions[0].message, "Roundtrip test");
}

#[test]
fn test_import_yaml_roundtrip() {
    let temp_dir = setup_test_dir();
    let file_path = temp_dir.path().join("yaml_roundtrip.aion");
    let signing_key = create_test_key();

    let init_options = create_init_options(9054, &signing_key, "YAML roundtrip");
    init_file(&file_path, b"yaml rules", &init_options).expect("Init failed");

    // Export to YAML
    let yaml = export_file(&file_path, ExportFormat::Yaml).expect("Export failed");

    // Import back
    let imported = import_yaml(&yaml).expect("Import failed");

    assert_eq!(imported.versions.len(), 1);
    assert_eq!(imported.versions[0].author_id, 9054);
}
