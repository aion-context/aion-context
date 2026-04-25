// SPDX-License-Identifier: MIT OR Apache-2.0
//! corpus_to_aion — transform a git corpus into a single signed `.aion` chain.
//!
//! Walks an external git repository's history, captures a chosen subtree
//! at each commit that touched the path filter, and replays each one as
//! a signed version into one growing `.aion` file. The result is a
//! cryptographically-bound, hash-chained record of how a body of
//! policy/spec/regulatory content evolved.
//!
//! Gated behind the `corpus-tool` feature so `cargo build` doesn't pull
//! in `tar` / `flate2`. Shells out to `git` (no libgit2 C deps).
//!
//! ## Provenance, not archival
//!
//! The resulting `.aion` file carries:
//!
//! - one encrypted_rules section (the LATEST commit's payload bytes), and
//! - the full hash-chained signature history (every historical
//!   `rules_hash` is recorded and signed).
//!
//! It does NOT carry the historical bytes. To replay any past version's
//! actual content, point an external content-addressed store
//! (S3 / IPFS / git-LFS / a transparency log) at the rule_hash values
//! the chain records.
//!
//! See `book/src/architecture/file-format.md` for the format-level
//! statement of this property.
//!
//! ## Run
//!
//! ```text
//! cargo run --release --features corpus-tool --example corpus_to_aion -- \
//!   --repo /path/to/repo \
//!   --subtree some/subdir \
//!   --filter '**/*.md' \
//!   --output /tmp/corpus.aion
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use aion_context::crypto::SigningKey;
use aion_context::key_registry::KeyRegistry;
use aion_context::operations::{
    commit_version, init_file, verify_file, CommitOptions, InitOptions,
};
use aion_context::types::AuthorId;

const DEFAULT_AUTHOR: u64 = 27_001;

#[derive(Debug)]
struct Args {
    repo: PathBuf,
    subtree: PathBuf,
    filter: String,
    output: PathBuf,
    author: u64,
    max_commits: Option<usize>,
    keep_checkout: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut repo: Option<PathBuf> = None;
    let mut subtree: Option<PathBuf> = None;
    let mut filter: Option<String> = None;
    let mut output: Option<PathBuf> = None;
    let mut author: u64 = DEFAULT_AUTHOR;
    let mut max_commits: Option<usize> = None;
    let mut keep_checkout = false;

    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--repo" => repo = Some(PathBuf::from(require(&mut iter, "--repo")?)),
            "--subtree" => subtree = Some(PathBuf::from(require(&mut iter, "--subtree")?)),
            "--filter" => filter = Some(require(&mut iter, "--filter")?),
            "--output" => output = Some(PathBuf::from(require(&mut iter, "--output")?)),
            "--author" => {
                author = require(&mut iter, "--author")?
                    .parse()
                    .map_err(|_| "--author must be a u64".to_string())?;
            }
            "--max-commits" => {
                max_commits = Some(
                    require(&mut iter, "--max-commits")?
                        .parse()
                        .map_err(|_| "--max-commits must be a non-negative integer".to_string())?,
                );
            }
            "--keep-checkout" => keep_checkout = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        repo: repo.ok_or_else(|| "missing --repo".to_string())?,
        subtree: subtree.ok_or_else(|| "missing --subtree".to_string())?,
        filter: filter.ok_or_else(|| "missing --filter".to_string())?,
        output: output.ok_or_else(|| "missing --output".to_string())?,
        author,
        max_commits,
        keep_checkout,
    })
}

fn require(iter: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{name} requires a value"))
}

fn print_help() {
    println!("corpus_to_aion — transform a git corpus into a signed .aion chain");
    println!();
    println!("USAGE:");
    println!("  corpus_to_aion --repo <PATH> --subtree <REL> --filter <PATHSPEC>");
    println!("                 --output <PATH> [OPTIONS]");
    println!();
    println!("REQUIRED:");
    println!("  --repo <PATH>          Path to a git repo (cloned externally)");
    println!("  --subtree <REL>        Relative subtree to capture per commit");
    println!("  --filter <PATHSPEC>    git pathspec — only commits touching it");
    println!("                         are replayed (e.g. '**/*.md')");
    println!("  --output <PATH>        Where to write the resulting .aion file");
    println!();
    println!("OPTIONS:");
    println!("  --author <ID>          Numeric author id (default: 27001)");
    println!("  --max-commits <N>      Cap to the first N commits");
    println!("  --keep-checkout        Don't restore repo HEAD to original ref");
    println!("  -h, --help             Show this help");
}

#[derive(Debug)]
struct CommitInfo {
    sha: String,
    date: String,
    subject: String,
}

fn list_commits(repo: &Path, filter: &str) -> Result<Vec<CommitInfo>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "log",
            "--reverse",
            "--format=%H|%ad|%s",
            "--date=short",
            "--",
        ])
        .arg(filter)
        .output()
        .map_err(|e| format!("git log failed to spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git log exited non-zero: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut commits = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(3, '|').collect();
        if parts.len() != 3 {
            continue;
        }
        commits.push(CommitInfo {
            sha: parts[0].to_string(),
            date: parts[1].to_string(),
            subject: parts[2].to_string(),
        });
    }
    Ok(commits)
}

fn current_ref(repo: &Path) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() || s == "HEAD" {
        // detached HEAD — fall back to the SHA so we can still restore
        let out2 = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&out2.stdout).trim().to_string())
    } else {
        Some(s)
    }
}

fn checkout(repo: &Path, refname: &str) -> Result<(), String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["checkout", "-q", refname])
        .output()
        .map_err(|e| format!("git checkout spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git checkout {refname} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Sentinel returned when the requested subtree does not exist at the
/// current checkout. The replay loop treats this as "skip this commit"
/// rather than as an error — early commits in a corpus often predate
/// the subtree's introduction.
const ERR_NO_SUBTREE: &str = "no_subtree_at_commit";

#[cfg(feature = "corpus-tool")]
fn tarball_subtree(repo: &Path, subtree: &Path) -> Result<Vec<u8>, String> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let abs_subtree = repo.join(subtree);
    if !abs_subtree.exists() {
        return Err(ERR_NO_SUBTREE.to_string());
    }
    let mut buf: Vec<u8> = Vec::new();
    {
        let gz = GzEncoder::new(&mut buf, Compression::default());
        let mut tar = tar::Builder::new(gz);
        let entries = walk_files(&abs_subtree);
        for path in &entries {
            let rel = path.strip_prefix(repo).unwrap_or(path);
            tar.append_path_with_name(path, rel)
                .map_err(|e| format!("tar append {}: {e}", path.display()))?;
        }
        tar.into_inner()
            .map_err(|e| format!("tar finalize: {e}"))?
            .finish()
            .map_err(|e| format!("gz finalize: {e}"))?;
    }
    Ok(buf)
}

#[cfg(not(feature = "corpus-tool"))]
fn tarball_subtree(_repo: &Path, _subtree: &Path) -> Result<Vec<u8>, String> {
    Err("corpus-tool feature not enabled".to_string())
}

fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

enum StepOutcome {
    Replayed,
    Skipped { reason: &'static str },
}

struct Replayer<'a> {
    args: &'a Args,
    key: SigningKey,
    registry: KeyRegistry,
    versions_written: u64,
    skipped: u64,
    payload_bytes_total: u64,
    sign_total: Duration,
}

impl<'a> Replayer<'a> {
    fn new(args: &'a Args) -> Self {
        let key = SigningKey::generate();
        let mut registry = KeyRegistry::new();
        registry
            .register_author(
                AuthorId::new(args.author),
                key.verifying_key(),
                key.verifying_key(),
                0,
            )
            .unwrap();
        Self {
            args,
            key,
            registry,
            versions_written: 0,
            skipped: 0,
            payload_bytes_total: 0,
            sign_total: Duration::ZERO,
        }
    }

    /// Replay one commit. Tiger Style: ≤ 60 lines.
    fn replay_one(&mut self, c: &CommitInfo) -> Result<StepOutcome, String> {
        checkout(&self.args.repo, &c.sha)?;
        let payload = match tarball_subtree(&self.args.repo, &self.args.subtree) {
            Ok(p) => p,
            Err(e) if e == ERR_NO_SUBTREE => {
                self.skipped += 1;
                return Ok(StepOutcome::Skipped {
                    reason: ERR_NO_SUBTREE,
                });
            }
            Err(e) => return Err(e),
        };
        let bytes = payload.len() as u64;
        self.payload_bytes_total += bytes;

        let short_sha = c.sha.get(..8).unwrap_or(&c.sha);
        let raw_msg = format!("{} {short_sha} {}", c.date, c.subject);
        let msg: String = raw_msg.chars().take(200).collect();

        let t = Instant::now();
        let author = AuthorId::new(self.args.author);
        if self.versions_written == 0 {
            init_file(
                &self.args.output,
                &payload,
                &InitOptions {
                    author_id: author,
                    signing_key: &self.key,
                    message: &msg,
                    timestamp: None,
                },
            )
            .map_err(|e| format!("init_file: {e}"))?;
        } else {
            let _ = commit_version(
                &self.args.output,
                &payload,
                &CommitOptions {
                    author_id: author,
                    signing_key: &self.key,
                    message: &msg,
                    timestamp: None,
                },
                &self.registry,
            )
            .map_err(|e| format!("commit_version: {e}"))?;
        }
        self.versions_written += 1;
        let elapsed = t.elapsed();
        self.sign_total += elapsed;

        emit_step_event(self.versions_written, short_sha, bytes, elapsed);
        println!(
            "  v{:02}  {short_sha}  {}  payload={:6} KB  elapsed={:>4} ms  {}",
            self.versions_written,
            c.date,
            bytes / 1024,
            elapsed.as_millis(),
            c.subject,
        );
        Ok(StepOutcome::Replayed)
    }
}

fn emit_step_event(version: u64, short_sha: &str, bytes: u64, elapsed: Duration) {
    tracing::info!(
        event = "corpus_replay_step",
        version,
        sha = short_sha,
        payload_kb = bytes / 1024,
        elapsed_ms = elapsed.as_millis() as u64,
    );
}

fn main() -> ExitCode {
    let env_filter = tracing_subscriber::EnvFilter::try_from_env("AION_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .try_init();

    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!("hint: run with --help for usage");
            return ExitCode::from(2);
        }
    };

    println!("=== corpus_to_aion ===");
    println!("repo:      {}", args.repo.display());
    println!("subtree:   {}", args.subtree.display());
    println!("filter:    {}", args.filter);
    println!("output:    {}", args.output.display());
    println!("author:    {}", args.author);
    if let Some(n) = args.max_commits {
        println!("cap:       first {n} commits");
    }
    println!();

    let original_ref = current_ref(&args.repo);

    let mut commits = match list_commits(&args.repo, &args.filter) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(event = "corpus_replay_failed", reason = "git_failed");
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    if let Some(n) = args.max_commits {
        commits.truncate(n);
    }
    println!("commits to replay: {}", commits.len());
    if commits.is_empty() {
        eprintln!("error: no commits matched the filter");
        return ExitCode::from(1);
    }

    let _ = std::fs::remove_file(&args.output);

    let t0 = Instant::now();
    tracing::info!(
        event = "corpus_replay_started",
        commits = commits.len() as u64
    );
    let mut replayer = Replayer::new(&args);
    for c in &commits {
        match replayer.replay_one(c) {
            Ok(StepOutcome::Replayed) => {}
            Ok(StepOutcome::Skipped { reason }) => {
                let short = c.sha.get(..8).unwrap_or(&c.sha);
                println!("  --   {short}  {}  skipped (reason={reason})", c.date);
                tracing::info!(event = "corpus_replay_skipped", sha = short, reason,);
            }
            Err(e) => {
                tracing::warn!(event = "corpus_replay_failed", reason = "commit_failed");
                eprintln!("error at commit {}: {e}", c.sha.get(..8).unwrap_or(&c.sha));
                restore_checkout(&args, original_ref.as_deref());
                return ExitCode::from(1);
            }
        }
    }
    let total = t0.elapsed();
    if replayer.versions_written == 0 {
        eprintln!("error: filter matched commits but none had the subtree present");
        restore_checkout(&args, original_ref.as_deref());
        return ExitCode::from(1);
    }

    restore_checkout(&args, original_ref.as_deref());

    let final_size = std::fs::metadata(&args.output).map_or(0, |m| m.len());

    println!();
    println!("=== summary ===");
    println!("commits considered:      {}", commits.len());
    println!("versions written:        {}", replayer.versions_written);
    println!("commits skipped:         {}", replayer.skipped);
    println!(
        "total payload (gzipped): {} KB",
        replayer.payload_bytes_total / 1024
    );
    println!("final .aion file size:   {} KB", final_size / 1024);
    println!("total wall time:         {} ms", total.as_millis());
    println!(
        "sign + write time:       {} ms",
        replayer.sign_total.as_millis()
    );
    if replayer.versions_written > 0 {
        println!(
            "average per version:     {} ms",
            replayer.sign_total.as_millis() / u128::from(replayer.versions_written)
        );
    }

    println!();
    println!("=== verifying the resulting .aion ===");
    let report = match verify_file(&args.output, &replayer.registry) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(event = "corpus_replay_failed", reason = "verify_failed");
            eprintln!("error: verify_file: {e}");
            return ExitCode::from(1);
        }
    };
    println!("structure_valid:        {}", report.structure_valid);
    println!("integrity_hash_valid:   {}", report.integrity_hash_valid);
    println!("hash_chain_valid:       {}", report.hash_chain_valid);
    println!("signatures_valid:       {}", report.signatures_valid);
    println!("is_valid:               {}", report.is_valid);
    println!("version_count:          {}", report.version_count);

    if report.is_valid {
        tracing::info!(
            event = "corpus_replay_completed",
            commits = commits.len() as u64,
            file_kb = final_size / 1024,
            total_ms = total.as_millis() as u64,
        );
        ExitCode::SUCCESS
    } else {
        tracing::warn!(event = "corpus_replay_failed", reason = "verify_invalid");
        ExitCode::from(1)
    }
}

fn restore_checkout(args: &Args, original_ref: Option<&str>) {
    if args.keep_checkout {
        return;
    }
    if let Some(r) = original_ref {
        let _ = checkout(&args.repo, r);
    }
}
