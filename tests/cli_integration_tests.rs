//! CLI Integration Tests for AION v2
//!
//! These tests verify the command-line interface by executing the aion binary
//! and validating its output and behavior.

#![allow(clippy::expect_used)] // Test code needs `.expect()` for clarity
#![allow(clippy::unwrap_used)] // Test assertions can use unwrap
#![allow(clippy::indexing_slicing)] // Test assertions use slice indexing on known inputs
#![allow(clippy::arithmetic_side_effects)] // Test bookkeeping uses unchecked arithmetic on small bounded values

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Get path to the built CLI binary
fn get_cli_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("Failed to get test executable path");
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps
    path.push("aion");
    path
}

/// Helper to run CLI commands
fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(get_cli_binary())
        .args(args)
        .output()
        .expect("Failed to execute CLI")
}

/// Helper to run CLI commands with stdin
fn run_cli_with_stdin(args: &[&str], stdin: &[u8]) -> std::process::Output {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(get_cli_binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn CLI");

    if let Some(ref mut stdin_handle) = child.stdin {
        stdin_handle
            .write_all(stdin)
            .expect("Failed to write stdin");
    }

    child.wait_with_output().expect("Failed to wait on CLI")
}

/// Setup a temp directory and generate a test key
fn setup_test_env() -> (TempDir, String) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    // Key IDs must be numeric
    let key_id = format!("{}", rand::random::<u32>() % 900000 + 100000);

    // Generate a key for testing
    let output = run_cli(&["key", "generate", "--id", &key_id]);
    assert!(
        output.status.success(),
        "Key generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    (temp_dir, key_id)
}

/// Cleanup test key
fn cleanup_key(key_id: &str) {
    let _ = run_cli(&["key", "delete", key_id, "--force"]);
}

// ============================================================================
// Help and Version Tests
// ============================================================================

#[test]
fn test_cli_help_displays_usage() {
    let output = run_cli(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AION"));
    assert!(stdout.contains("init"));
    assert!(stdout.contains("commit"));
    assert!(stdout.contains("verify"));
    assert!(stdout.contains("show"));
    assert!(stdout.contains("key"));
}

#[test]
fn test_cli_version_displays_version() {
    let output = run_cli(&["--version"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("aion") || stdout.contains("0."));
}

#[test]
fn test_cli_subcommand_help() {
    for subcommand in &["init", "commit", "verify", "show", "key"] {
        let output = run_cli(&[subcommand, "--help"]);
        assert!(
            output.status.success(),
            "{} help failed: {}",
            subcommand,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// ============================================================================
// Key Management CLI Tests
// ============================================================================

/// Tests key generation and listing
/// Note: This test may fail if the keyring prompts for password
#[test]
#[ignore = "Requires keyring access which may prompt for password"]
fn test_cli_key_generate_and_list() {
    let key_id = format!("{}", rand::random::<u32>() % 900000 + 200000);

    // Generate key
    let output = run_cli(&["key", "generate", "--id", &key_id]);
    assert!(
        output.status.success(),
        "Key generate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List keys - should include our key
    let output = run_cli(&["key", "list"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&key_id),
        "Key list should contain {key_id}: {stdout}"
    );

    // Cleanup
    cleanup_key(&key_id);
}

/// Tests key export/import roundtrip
/// Note: This test requires password input which can't be automated easily
#[test]
#[ignore = "Requires interactive password input"]
fn test_cli_key_export_import_roundtrip() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_id = format!("{}", rand::random::<u32>() % 900000 + 300000);
    let export_path = temp_dir.path().join("exported.key");

    // Generate key
    let output = run_cli(&["key", "generate", "--id", &key_id]);
    assert!(output.status.success());

    // Export key (with password via env or default)
    let output = Command::new(get_cli_binary())
        .args([
            "key",
            "export",
            &key_id,
            "--output",
            export_path.to_str().unwrap(),
        ])
        .env("AION_KEY_PASSWORD", "testpassword123")
        .output()
        .expect("Export failed");

    assert!(
        output.status.success(),
        "Key export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(export_path.exists(), "Export file should exist");

    // Delete original key
    run_cli(&["key", "delete", &key_id, "--force"]);

    // Import key
    let new_key_id = format!("{}", rand::random::<u32>() % 900000 + 400000);
    let output = Command::new(get_cli_binary())
        .args([
            "key",
            "import",
            export_path.to_str().unwrap(),
            "--id",
            &new_key_id,
        ])
        .env("AION_KEY_PASSWORD", "testpassword123")
        .output()
        .expect("Import failed");

    assert!(
        output.status.success(),
        "Key import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify imported key is listed
    let output = run_cli(&["key", "list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&new_key_id));

    // Cleanup
    cleanup_key(&new_key_id);
}

#[test]
fn test_cli_key_delete_requires_confirmation_or_force() {
    let key_id = format!("{}", rand::random::<u32>() % 900000 + 500000);

    // Generate key
    run_cli(&["key", "generate", "--id", &key_id]);

    // Delete with --force should succeed
    let output = run_cli(&["key", "delete", &key_id, "--force"]);
    assert!(output.status.success());

    // Key should no longer be listed
    let output = run_cli(&["key", "list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(&key_id));
}

// ============================================================================
// Init Command CLI Tests
// ============================================================================

#[test]
fn test_cli_init_creates_file() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("test.aion");
    let rules_path = temp_dir.path().join("rules.txt");

    // Create rules file
    fs::write(&rules_path, "threshold: 100\nmode: strict").expect("Failed to write rules");

    // Init file
    let output = run_cli(&[
        "init",
        file_path.to_str().unwrap(),
        "--rules",
        rules_path.to_str().unwrap(),
        "--author",
        "1001",
        "--key",
        &key_id,
        "--message",
        "Initial version",
    ]);

    assert!(
        output.status.success(),
        "Init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(file_path.exists(), "AION file should be created");

    cleanup_key(&key_id);
}

#[test]
fn test_cli_init_with_stdin_rules() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("stdin_test.aion");

    // Init with stdin rules
    let output = run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "1002",
            "--key",
            &key_id,
            "--message",
            "From stdin",
        ],
        b"rules from stdin",
    );

    assert!(
        output.status.success(),
        "Init with stdin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(file_path.exists());

    cleanup_key(&key_id);
}

#[test]
fn test_cli_init_fails_if_file_exists() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("exists.aion");

    // Create file first time
    let output = run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "1003",
            "--key",
            &key_id,
        ],
        b"initial",
    );
    assert!(output.status.success());

    // Try to create again - should fail
    let output = run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "1003",
            "--key",
            &key_id,
        ],
        b"second",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exists") || stderr.contains("already"),
        "Should mention file exists: {stderr}"
    );

    cleanup_key(&key_id);
}

// ============================================================================
// Commit Command CLI Tests
// ============================================================================

#[test]
fn test_cli_commit_adds_version() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("commit_test.aion");

    // Init file
    let output = run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "2001",
            "--key",
            &key_id,
        ],
        b"v1 rules",
    );
    assert!(output.status.success());

    // Commit new version
    let output = run_cli_with_stdin(
        &[
            "commit",
            file_path.to_str().unwrap(),
            "--author",
            "2001",
            "--key",
            &key_id,
            "--message",
            "Updated rules",
        ],
        b"v2 rules",
    );

    assert!(
        output.status.success(),
        "Commit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify version count
    let output = run_cli(&["show", file_path.to_str().unwrap(), "info"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains('2') || stdout.contains("versions"),
        "Should show 2 versions: {stdout}"
    );

    cleanup_key(&key_id);
}

#[test]
fn test_cli_commit_with_different_author() {
    let (temp_dir, key_id1) = setup_test_env();
    let key_id2 = format!("{}", rand::random::<u32>() % 900000 + 600000);
    run_cli(&["key", "generate", "--id", &key_id2]);

    let file_path = temp_dir.path().join("multi_author.aion");

    // Init with author 1
    let output = run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "3001",
            "--key",
            &key_id1,
        ],
        b"author1 rules",
    );
    assert!(output.status.success());

    // Commit with author 2
    let output = run_cli_with_stdin(
        &[
            "commit",
            file_path.to_str().unwrap(),
            "--author",
            "3002",
            "--key",
            &key_id2,
            "--message",
            "Author 2 update",
        ],
        b"author2 rules",
    );
    assert!(output.status.success());

    // Check history shows both authors
    let output = run_cli(&["show", file_path.to_str().unwrap(), "history"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("3001") || stdout.contains("Author"));
    assert!(stdout.contains("3002") || stdout.contains("Author"));

    cleanup_key(&key_id1);
    cleanup_key(&key_id2);
}

// ============================================================================
// Verify Command CLI Tests
// ============================================================================

#[test]
fn test_cli_verify_valid_file() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("verify_test.aion");

    // Create file
    let output = run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "4001",
            "--key",
            &key_id,
        ],
        b"test rules",
    );
    assert!(output.status.success());

    // Verify file
    let output = run_cli(&["verify", file_path.to_str().unwrap()]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("valid")
            || stdout.to_lowercase().contains("ok")
            || stdout.contains("✓")
            || stdout.contains("passed"),
        "Should indicate valid: {stdout}"
    );

    cleanup_key(&key_id);
}

#[test]
fn test_cli_verify_verbose_output() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("verbose_verify.aion");

    // Create file
    run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "4002",
            "--key",
            &key_id,
        ],
        b"rules",
    );

    // Verify with verbose
    let output = run_cli(&["verify", file_path.to_str().unwrap(), "--verbose"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Verbose should show more details
    assert!(
        stdout.len() > 50,
        "Verbose output should be detailed: {stdout}"
    );

    cleanup_key(&key_id);
}

#[test]
fn test_cli_verify_corrupted_file_fails() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("corrupted.aion");

    // Create file
    run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "4003",
            "--key",
            &key_id,
        ],
        b"original rules",
    );

    // Corrupt the file
    let mut data = fs::read(&file_path).expect("Read failed");
    if data.len() > 100 {
        data[100] ^= 0xFF;
        fs::write(&file_path, data).expect("Write failed");
    }

    // Verify should fail or report invalid
    let output = run_cli(&["verify", file_path.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // Either non-zero exit or indicates invalid
    assert!(
        !output.status.success()
            || combined.to_lowercase().contains("invalid")
            || combined.to_lowercase().contains("fail")
            || combined.to_lowercase().contains("error"),
        "Should indicate corruption: exit={}, output={}",
        output.status,
        combined
    );

    cleanup_key(&key_id);
}

// ============================================================================
// Show Command CLI Tests
// ============================================================================

#[test]
fn test_cli_show_rules() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("show_rules.aion");
    let rules_content = "threshold: 500\nmode: relaxed";

    // Create file
    run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "5001",
            "--key",
            &key_id,
        ],
        rules_content.as_bytes(),
    );

    // Show rules
    let output = run_cli(&["show", file_path.to_str().unwrap(), "rules"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("threshold") || stdout.contains("500"),
        "Should show rules content: {stdout}"
    );

    cleanup_key(&key_id);
}

#[test]
fn test_cli_show_history() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("show_history.aion");

    // Create file with multiple versions
    run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "5002",
            "--key",
            &key_id,
            "--message",
            "First commit",
        ],
        b"v1",
    );

    run_cli_with_stdin(
        &[
            "commit",
            file_path.to_str().unwrap(),
            "--author",
            "5002",
            "--key",
            &key_id,
            "--message",
            "Second commit",
        ],
        b"v2",
    );

    // Show history
    let output = run_cli(&["show", file_path.to_str().unwrap(), "history"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("First") || stdout.contains('1'));
    assert!(stdout.contains("Second") || stdout.contains('2'));

    cleanup_key(&key_id);
}

#[test]
fn test_cli_show_signatures() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("show_sigs.aion");

    // Create file
    run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "5003",
            "--key",
            &key_id,
        ],
        b"rules",
    );

    // Show signatures
    let output = run_cli(&["show", file_path.to_str().unwrap(), "signatures"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show signature info
    assert!(stdout.len() > 10, "Should show signature info: {stdout}");

    cleanup_key(&key_id);
}

#[test]
fn test_cli_show_info() {
    let (temp_dir, key_id) = setup_test_env();
    let file_path = temp_dir.path().join("show_info.aion");

    // Create file
    run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "5004",
            "--key",
            &key_id,
        ],
        b"rules",
    );

    // Show info
    let output = run_cli(&["show", file_path.to_str().unwrap(), "info"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show file metadata
    assert!(
        stdout.contains("version") || stdout.contains("author") || stdout.contains("5004"),
        "Should show file info: {stdout}"
    );

    cleanup_key(&key_id);
}

// ============================================================================
// Error Case CLI Tests
// ============================================================================

#[test]
fn test_cli_invalid_subcommand_fails() {
    let output = run_cli(&["nonexistent"]);
    assert!(!output.status.success());
}

#[test]
fn test_cli_missing_required_args_fails() {
    // Init without required args
    let output = run_cli(&["init"]);
    assert!(!output.status.success());

    // Commit without required args
    let output = run_cli(&["commit"]);
    assert!(!output.status.success());
}

#[test]
fn test_cli_verify_nonexistent_file_fails() {
    let output = run_cli(&["verify", "/nonexistent/path/file.aion"]);
    assert!(!output.status.success());
}

#[test]
fn test_cli_show_nonexistent_file_fails() {
    let output = run_cli(&["show", "/nonexistent/path/file.aion", "info"]);
    assert!(!output.status.success());
}

#[test]
fn test_cli_commit_nonexistent_file_fails() {
    let key_id = format!("{}", rand::random::<u32>() % 900000 + 700000);
    run_cli(&["key", "generate", "--id", &key_id]);

    let output = run_cli_with_stdin(
        &[
            "commit",
            "/nonexistent/path/file.aion",
            "--author",
            "9999",
            "--key",
            &key_id,
            "--message",
            "test",
        ],
        b"rules",
    );
    assert!(!output.status.success());

    cleanup_key(&key_id);
}

#[test]
fn test_cli_init_with_nonexistent_key_fails() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("test.aion");

    let output = run_cli_with_stdin(
        &[
            "init",
            file_path.to_str().unwrap(),
            "--author",
            "1000",
            "--key",
            "nonexistent_key_12345",
        ],
        b"rules",
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("key") || stderr.contains("not found") || stderr.contains("error"),
        "Should indicate key error: {stderr}"
    );
}
