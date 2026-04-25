//! policy_loop — a tight-loop AI agent over a signed `.aion` policy file.
//!
//! Most agent frameworks ship policies as unsigned YAML/JSON. Anyone with
//! filesystem access can mutate them, and there is no audit trail of policy
//! changes. This example shows the alternative: a tiny synthetic agent
//! re-verifies its policy file on every tick, refuses to act when the file
//! fails the four guarantees (structure, integrity, hash chain, registry-
//! aware signature per RFC-0034), and quietly picks up new versions when
//! the operator commits them.
//!
//! The example is self-contained — a single `cargo run` plays both the
//! operator and the agent so the full lifecycle is visible without manual
//! intervention. Phases:
//!
//!   1. Operator initializes the policy file (v1, lenient — all actions allowed).
//!   2. Agent runs 5 ticks under v1.
//!   3. Operator commits v2 (tightened — only `fetch_url`).
//!   4. Agent runs 5 ticks under v2 (now blocks 4 of the 5 actions).
//!   5. Operator (or adversary) flips one byte mid-file.
//!   6. Agent runs 3 ticks — every tick REFUSED with reason=integrity_hash_mismatch.
//!   7. Operator restores the file from a clean policy.
//!   8. Agent runs 2 ticks — back to normal under the restored policy.
//!
//! Run:
//!
//! ```text
//! cargo run --release --example policy_loop
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

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use aion_context::crypto::SigningKey;
use aion_context::key_registry::KeyRegistry;
use aion_context::operations::{
    commit_version, init_file, show_current_rules, verify_file, CommitOptions, InitOptions,
    VerificationReport,
};
use aion_context::types::AuthorId;

const TICK_MS: u64 = 400;
const OPERATOR_AUTHOR: u64 = 70_001;
const ACTIONS: &[&str] = &[
    "fetch_url",
    "send_email",
    "exec_shell",
    "write_file",
    "read_secret",
];

const POLICY_V1: &[u8] = b"# policy v1 (lenient)\n\
                            allow: fetch_url\n\
                            allow: send_email\n\
                            allow: exec_shell\n\
                            allow: write_file\n\
                            allow: read_secret\n";

const POLICY_V2: &[u8] = b"# policy v2 (tightened: incident response posture)\n\
                            allow: fetch_url\n\
                            block: send_email\n\
                            block: exec_shell\n\
                            block: write_file\n\
                            block: read_secret\n";

#[derive(Debug, Clone)]
struct Policy {
    allow: HashSet<String>,
}

impl Policy {
    fn parse(rules: &[u8]) -> Self {
        let text = std::str::from_utf8(rules).unwrap_or("");
        let mut allow = HashSet::new();
        for raw in text.lines() {
            let line = raw.trim();
            if let Some(action) = line.strip_prefix("allow:") {
                allow.insert(action.trim().to_string());
            }
        }
        Self { allow }
    }

    fn permits(&self, action: &str) -> bool {
        self.allow.contains(action)
    }
}

#[derive(Debug)]
enum Decision {
    Allowed {
        action: String,
        version: u64,
    },
    Blocked {
        action: String,
        version: u64,
    },
    Refused {
        reason: &'static str,
        detail: String,
    },
}

struct Agent {
    policy_path: PathBuf,
    registry: KeyRegistry,
    last_version: u64,
    tick_seq: u64,
}

impl Agent {
    fn new(policy_path: PathBuf, registry: KeyRegistry) -> Self {
        Self {
            policy_path,
            registry,
            last_version: 0,
            tick_seq: 0,
        }
    }

    /// One agent step: re-verify the policy file, classify the next work
    /// item, emit a structured decision. Tiger Style: ≤ 60 body lines.
    fn tick(&mut self) -> Decision {
        let action = ACTIONS[(self.tick_seq as usize) % ACTIONS.len()].to_string();
        self.tick_seq += 1;

        let report = match verify_file(&self.policy_path, &self.registry) {
            Ok(r) => r,
            Err(e) => {
                return Decision::Refused {
                    reason: "verify_error",
                    detail: e.to_string(),
                }
            }
        };
        if !report.is_valid {
            return Decision::Refused {
                reason: classify_invalid(&report),
                detail: report.errors.join("; "),
            };
        }

        let version = report.version_count;
        if version != self.last_version {
            println!(
                "  ↻ policy update accepted: v{} → v{}",
                self.last_version, version
            );
            self.last_version = version;
        }

        let rules = match show_current_rules(&self.policy_path) {
            Ok(r) => r,
            Err(e) => {
                return Decision::Refused {
                    reason: "rules_unreadable",
                    detail: e.to_string(),
                }
            }
        };
        let policy = Policy::parse(&rules);

        if policy.permits(&action) {
            Decision::Allowed { action, version }
        } else {
            Decision::Blocked { action, version }
        }
    }
}

/// Map a failed `VerificationReport` to a bounded reason code.
fn classify_invalid(report: &VerificationReport) -> &'static str {
    if !report.structure_valid {
        "structure_invalid"
    } else if !report.integrity_hash_valid {
        "integrity_hash_mismatch"
    } else if !report.hash_chain_valid {
        "hash_chain_broken"
    } else if !report.signatures_valid {
        "signature_invalid"
    } else {
        "unknown"
    }
}

fn print_decision(idx: u64, d: &Decision) {
    match d {
        Decision::Allowed { action, version } => {
            println!("  tick #{idx:02}  v{version}  decision=ALLOW   action={action}");
        }
        Decision::Blocked { action, version } => {
            println!("  tick #{idx:02}  v{version}  decision=BLOCK   action={action}");
        }
        Decision::Refused { reason, detail } => {
            println!("  tick #{idx:02}        decision=REFUSE  reason={reason}  ({detail})");
        }
    }
}

fn run_ticks(agent: &mut Agent, n: u64, label: &str) {
    println!();
    println!("─── {label} ───────────────────────────────────────────────");
    for _ in 0..n {
        let d = agent.tick();
        print_decision(agent.tick_seq, &d);
        sleep(Duration::from_millis(TICK_MS));
    }
}

fn init_demo(path: &Path, key: &SigningKey, author: AuthorId) -> KeyRegistry {
    if path.exists() {
        std::fs::remove_file(path).unwrap();
    }
    init_file(
        path,
        POLICY_V1,
        &InitOptions {
            author_id: author,
            signing_key: key,
            message: "genesis: lenient policy",
            timestamp: None,
        },
    )
    .unwrap();

    let mut reg = KeyRegistry::new();
    reg.register_author(author, key.verifying_key(), key.verifying_key(), 0)
        .unwrap();
    reg
}

fn commit_tightened(path: &Path, key: &SigningKey, author: AuthorId, registry: &KeyRegistry) {
    let _ = commit_version(
        path,
        POLICY_V2,
        &CommitOptions {
            author_id: author,
            signing_key: key,
            message: "tightened: incident response posture",
            timestamp: None,
        },
        registry,
    )
    .unwrap();
}

fn tamper(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    let i = bytes.len() / 2;
    bytes[i] ^= 0x01;
    std::fs::write(path, bytes).unwrap();
}

fn banner(title: &str) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║ {title:<69} ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝");
}

fn main() {
    let path = std::env::temp_dir().join("aion_policy_loop_demo.aion");
    let key = SigningKey::generate();
    let author = AuthorId::new(OPERATOR_AUTHOR);

    banner("policy_loop — tight-loop agent over a signed .aion policy");
    println!("  policy file:  {}", path.display());
    println!("  operator:     author {OPERATOR_AUTHOR}");
    println!("  tick:         every {TICK_MS}ms");

    let registry = init_demo(&path, &key, author);
    println!();
    println!("Phase 1 — operator init: policy v1 (lenient)");
    let mut agent = Agent::new(path.clone(), registry);

    run_ticks(&mut agent, 5, "Phase 2 — agent under policy v1");

    println!();
    println!("Phase 3 — operator commits policy v2 (tightened)");
    commit_tightened(&path, &key, author, &agent.registry);

    run_ticks(&mut agent, 5, "Phase 4 — agent under policy v2");

    println!();
    println!("Phase 5 — operator (adversary?) flips one byte in the file");
    tamper(&path);

    run_ticks(&mut agent, 3, "Phase 6 — agent under tampered file");

    println!();
    println!("Phase 7 — operator restores file (re-init from clean policy)");
    agent.registry = init_demo(&path, &key, author);
    agent.last_version = 0;

    run_ticks(&mut agent, 2, "Phase 8 — agent after restoration");

    println!();
    println!("✓ demo complete");
    let _ = std::fs::remove_file(&path);
}
