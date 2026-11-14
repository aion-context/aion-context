// SPDX-License-Identifier: MIT OR Apache-2.0
//! Golden tests for every `--format yaml` output of the `aion` CLI.
//!
//! `--format yaml` output is covered by the semver promise in
//! `book/src/architecture/stability.md`, so a change of YAML backend
//! (issue #191) must show up as a diff against `tests/golden/yaml/`.
//!
//! Keys, signatures, timestamps and file ids differ between runs, so
//! their values are masked by field name before comparison. Everything
//! else (key order, quoting, block scalars, nulls, list layout) is
//! pinned byte for byte.
//!
//! Regenerate with `AION_UPDATE_GOLDEN=1 cargo test --test cli_yaml_golden`.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

const VOLATILE_KEYS: &[&str] = &[
    "digest",
    "file_id",
    "timestamp",
    "parent_hash",
    "public_key",
    "public_key_hex",
    "public_key_prefix",
    "pubkey_prefix",
    "signature_hex",
    "sig",
];

const MASK: &str = "<MASKED>";

fn aion(args: &[&str], stdin: Option<&[u8]>) -> Output {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_aion"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aion");
    if let Some(bytes) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(bytes)
            .expect("write stdin");
    }
    child.wait_with_output().expect("wait aion")
}

fn aion_ok(args: &[&str], stdin: Option<&[u8]>) -> String {
    let out = aion(args, stdin);
    assert!(
        out.status.success(),
        "aion {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8 stdout")
}

/// Masks the value of every line whose key is in `VOLATILE_KEYS`, and
/// every `- <scalar>` item of a list that such a key opens.
fn mask_volatile(yaml: &str) -> String {
    let mut out = String::with_capacity(yaml.len());
    let mut list_column: Option<usize> = None;
    for line in yaml.lines() {
        if let Some(col) = list_column {
            let is_item = line.len() > col
                && line[..col].bytes().all(|b| b == b' ')
                && line[col..].starts_with("- ");
            if is_item {
                out.push_str(&line[..col + 2]);
                out.push_str(MASK);
                out.push('\n');
                continue;
            }
            list_column = None;
        }
        out.push_str(&mask_line(line, &mut list_column));
        out.push('\n');
    }
    out
}

fn mask_line(line: &str, list_column: &mut Option<usize>) -> String {
    let body = line.trim_start_matches([' ', '-']);
    let key_col = line.len() - body.len();
    let Some((key, value)) = body.split_once(':') else {
        return line.to_string();
    };
    if !VOLATILE_KEYS.contains(&key) {
        return line.to_string();
    }
    if value.trim().is_empty() {
        *list_column = Some(key_col);
        return line.to_string();
    }
    if value.trim() == "null" {
        return line.to_string();
    }
    format!("{}{key}: {MASK}", &line[..key_col])
}

struct Scenario {
    _dir: TempDir,
    root: PathBuf,
    registry: PathBuf,
    archive: PathBuf,
    file: PathBuf,
    bundle: PathBuf,
    keys: [String; 2],
}

impl Drop for Scenario {
    fn drop(&mut self) {
        for key in &self.keys {
            let _ = aion(&["key", "delete", key, "--force"], None);
        }
    }
}

fn path(p: &Path) -> &str {
    p.to_str().expect("utf8 path")
}

fn build_scenario() -> Scenario {
    let dir = TempDir::new().expect("tempdir");
    let root = dir.path().to_path_buf();
    let op = format!("{}", rand::random::<u32>() % 900_000 + 100_000);
    let master = format!("{}", rand::random::<u32>() % 900_000 + 100_000);
    let s = Scenario {
        registry: root.join("registry.json"),
        archive: root.join("archive"),
        file: root.join("archive").join("policy.aion"),
        bundle: root.join("bundle"),
        root,
        _dir: dir,
        keys: [op, master],
    };
    fs::create_dir_all(&s.archive).expect("mkdir archive");
    let [op, master] = &s.keys;
    aion_ok(&["key", "generate", "--id", op], None);
    aion_ok(&["key", "generate", "--id", master], None);
    let reg = path(&s.registry);
    aion_ok(
        &[
            "registry", "pin", "--author", "8001", "--key", op, "--master", master, "--output", reg,
        ],
        None,
    );
    commit_versions(&s);
    seal_release(&s);
    s
}

fn commit_versions(s: &Scenario) {
    let op = &s.keys[0];
    let file = path(&s.file);
    let init = ["init", "--public", file, "--author", "8001", "--key", op];
    let msg = "Initial: \"quoted\" yes";
    let args = [&init[..], &["--message", msg]].concat();
    aion_ok(&args, Some(b"threshold: 100\n"));
    let commit = [
        "commit",
        "--public",
        file,
        "--author",
        "8001",
        "--key",
        op,
        "--registry",
    ];
    let args = [
        &commit[..],
        &[path(&s.registry), "--message", "multi\nline"],
    ]
    .concat();
    aion_ok(&args, Some(b"threshold: 200\n"));
}

fn seal_release(s: &Scenario) {
    let primary = s.root.join("model.bin");
    fs::write(&primary, vec![0xAA_u8; 4096]).expect("write primary");
    aion_ok(
        &[
            "release",
            "seal",
            "--primary",
            path(&primary),
            "--primary-name",
            "model.safetensors",
            "--model-name",
            "cirrus-7b-safety",
            "--model-version",
            "0.3.1",
            "--model-format",
            "safetensors",
            "--framework",
            "pytorch:2.3.1",
            "--license",
            "Apache-2.0:weights",
            "--safety-attestation",
            "rlhf_alignment:PASS",
            "--export-control",
            "US-EAR:EAR99",
            "--builder-id",
            "https://ci.example/run/1",
            "--aion-version",
            "1",
            "--author",
            "8001",
            "--key",
            &s.keys[0],
            "--out-dir",
            path(&s.bundle),
        ],
        None,
    );
}

fn yaml_outputs(s: &Scenario) -> Vec<(&'static str, String)> {
    let file = path(&s.file);
    let reg = path(&s.registry);
    let show = |sub: &str| aion_ok(&["show", file, "--registry", reg, "-f", "yaml", sub], None);
    let raw = vec![
        (
            "verify",
            aion_ok(&["verify", file, "--registry", reg, "-f", "yaml"], None),
        ),
        ("show_history", show("history")),
        ("show_signatures", show("signatures")),
        ("show_info", show("info")),
        (
            "export",
            aion_ok(&["export", file, "--registry", reg, "-f", "yaml"], None),
        ),
        (
            "archive_verify",
            aion_ok(
                &[
                    "archive",
                    "verify",
                    path(&s.archive),
                    "--registry",
                    reg,
                    "-f",
                    "yaml",
                ],
                None,
            ),
        ),
        (
            "release_inspect",
            aion_ok(
                &[
                    "release",
                    "inspect",
                    "--bundle",
                    path(&s.bundle),
                    "-f",
                    "yaml",
                ],
                None,
            ),
        ),
    ];
    let root = path(&s.root);
    raw.into_iter()
        .map(|(name, out)| (name, mask_volatile(&out.replace(root, "<TMP>"))))
        .collect()
}

fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/yaml")
        .join(format!("{name}.yaml"))
}

#[test]
fn yaml_masking_is_complete() {
    let first = yaml_outputs(&build_scenario());
    let second = yaml_outputs(&build_scenario());
    for ((name, a), (_, b)) in first.iter().zip(&second) {
        assert_eq!(a, b, "{name}: a run-dependent value is not masked");
    }
}

#[test]
fn yaml_output_matches_golden() {
    let update = std::env::var_os("AION_UPDATE_GOLDEN").is_some();
    for (name, actual) in yaml_outputs(&build_scenario()) {
        let golden = golden_path(name);
        if update {
            fs::create_dir_all(golden.parent().expect("parent")).expect("mkdir golden");
            fs::write(&golden, &actual).expect("write golden");
            continue;
        }
        let expected = fs::read_to_string(&golden).expect("golden file; set AION_UPDATE_GOLDEN=1");
        assert_eq!(
            actual,
            expected,
            "{name}: YAML output drifted from {}",
            golden.display()
        );
    }
}

#[test]
fn masking_hides_values_and_list_items_only() {
    let input = "a: 1\nfile_id: 42\nrules_hash:\n- 7\nparent_hash:\n- 9\n- 10\nparent_hash: null\n- sig: abc\n  keyid: k\n";
    let expected = "a: 1\nfile_id: <MASKED>\nrules_hash:\n- 7\nparent_hash:\n- <MASKED>\n- <MASKED>\nparent_hash: null\n- sig: <MASKED>\n  keyid: k\n";
    assert_eq!(mask_volatile(input), expected);
}
