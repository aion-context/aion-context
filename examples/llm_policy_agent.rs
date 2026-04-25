// SPDX-License-Identifier: MIT OR Apache-2.0
//! llm_policy_agent — Claude proposes, the .aion policy gates.
//!
//! A real LLM-driven sibling of `policy_loop`. For each synthetic
//! ticket, the example asks Claude what action to take, then runs
//! the proposed action through a signed `.aion` policy file. The
//! policy is the enforcement boundary — even a jailbroken or
//! prompt-injected LLM cannot bypass it, because the gate lives
//! outside the model.
//!
//! The example is gated behind the `llm-agent-example` feature so
//! the default build doesn't pull in an HTTP client. The Anthropic
//! API key is read from `ANTHROPIC_API_KEY` and never logged.
//!
//! Run:
//!
//! ```text
//! ANTHROPIC_API_KEY=sk-ant-... \
//!   cargo run --release --features llm-agent-example \
//!     --example llm_policy_agent
//! ```
//!
//! Optional envs:
//! - `AION_LOG=info`              — show structured tracing emits
//! - `LLM_POLICY_MODEL=...`       — override default Claude model
//! - `LLM_POLICY_NO_NETWORK=1`    — skip the API call, use a fixed
//!   proposer (handy for CI / offline demos)

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
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use aion_context::audit::ActionCode;
use aion_context::crypto::SigningKey;
use aion_context::key_registry::KeyRegistry;
use aion_context::operations::{
    commit_version, init_file, show_current_rules, verify_file, CommitOptions, InitOptions,
    VerificationReport,
};
use aion_context::parser::AionParser;
use aion_context::types::AuthorId;

const OPERATOR_AUTHOR: u64 = 81_001;
const ACTIONS: &[&str] = &[
    "fetch_url",
    "send_email",
    "exec_shell",
    "write_file",
    "read_secret",
];
const ENV_API_KEY: &str = "ANTHROPIC_API_KEY";
const ENV_MODEL: &str = "LLM_POLICY_MODEL";
const ENV_OFFLINE: &str = "LLM_POLICY_NO_NETWORK";
const DEFAULT_MODEL: &str = "claude-sonnet-4-6";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const API_URL: &str = "https://api.anthropic.com/v1/messages";
const MAX_TOKENS: u32 = 32;
const SYSTEM_PROMPT: &str = "You are an automation agent. \
    Reply with EXACTLY ONE word from this set: \
    fetch_url, send_email, exec_shell, write_file, read_secret. \
    No prose, no punctuation, no explanation.";

const TICKETS: &[&str] = &[
    "Customer reports 503 on /pricing — investigate the upstream.",
    "Engineering asks: notify on-call about the staging deploy.",
    "Marketing wants the latest signup count from last week.",
    "Compliance asks: archive the H2 incident report to cold storage.",
    "A new employee needs the welcome email sent now.",
];

const POLICY_V1: &[u8] = b"# policy v1 (lenient)\n\
                            allow: fetch_url\n\
                            allow: send_email\n\
                            allow: exec_shell\n\
                            allow: write_file\n\
                            allow: read_secret\n";

const POLICY_V2: &[u8] = b"# policy v2 (incident-response)\n\
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

struct LlmClient {
    api_key: String,
    model: String,
    offline: bool,
}

impl LlmClient {
    fn from_env() -> Result<Self, &'static str> {
        let offline = std::env::var(ENV_OFFLINE)
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let api_key = if offline {
            String::new()
        } else {
            let raw = std::env::var(ENV_API_KEY).unwrap_or_default();
            if raw.is_empty() {
                return Err(
                    "ANTHROPIC_API_KEY not set or empty; export it or set LLM_POLICY_NO_NETWORK=1",
                );
            }
            raw
        };
        let model = std::env::var(ENV_MODEL)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_MODEL.to_string());
        Ok(Self {
            api_key,
            model,
            offline,
        })
    }

    fn propose_action(&self, ticket: &str, tick_seq: u64) -> String {
        if self.offline {
            return offline_proposer(tick_seq);
        }
        match self.call_anthropic(ticket) {
            Ok(text) => normalize_action(&text),
            Err(reason) => {
                tracing::warn!(event = "llm_call_failed", reason);
                "unknown".to_string()
            }
        }
    }

    #[cfg(feature = "llm-agent-example")]
    fn call_anthropic(&self, ticket: &str) -> Result<String, &'static str> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": ticket}],
        });
        let resp = ureq::post(API_URL)
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", ANTHROPIC_VERSION)
            .set("content-type", "application/json")
            .timeout(Duration::from_secs(30))
            .send_json(body)
            .map_err(|_| "http_error")?;
        let json: serde_json::Value = resp.into_json().map_err(|_| "decode_error")?;
        let text = json
            .get("content")
            .and_then(|c| c.get(0))
            .and_then(|m| m.get("text"))
            .and_then(|t| t.as_str())
            .ok_or("missing_text")?;
        Ok(text.to_string())
    }

    #[cfg(not(feature = "llm-agent-example"))]
    fn call_anthropic(&self, _ticket: &str) -> Result<String, &'static str> {
        Err("network feature not enabled")
    }
}

fn offline_proposer(tick_seq: u64) -> String {
    ACTIONS[(tick_seq as usize) % ACTIONS.len()].to_string()
}

fn normalize_action(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .to_lowercase();
    if ACTIONS.iter().any(|a| *a == cleaned) {
        cleaned
    } else {
        "unknown".to_string()
    }
}

#[derive(Debug)]
enum Decision {
    Executed {
        action: String,
        version: u64,
    },
    Blocked {
        action: String,
        version: u64,
        reason: &'static str,
    },
    Refused {
        reason: &'static str,
        detail: String,
    },
}

struct Agent {
    policy_path: PathBuf,
    registry: KeyRegistry,
    llm: LlmClient,
    last_version: u64,
    tick_seq: u64,
}

impl Agent {
    fn new(policy_path: PathBuf, registry: KeyRegistry, llm: LlmClient) -> Self {
        Self {
            policy_path,
            registry,
            llm,
            last_version: 0,
            tick_seq: 0,
        }
    }

    /// Tiger Style: ≤ 60 body lines.
    fn handle(&mut self, ticket: &str) -> Decision {
        self.tick_seq += 1;
        let proposed = self.llm.propose_action(ticket, self.tick_seq);
        tracing::info!(event = "llm_proposed", action = %proposed, tick = self.tick_seq);

        let report = match verify_file(&self.policy_path, &self.registry) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(event = "agent_refused", reason = "verify_error");
                return Decision::Refused {
                    reason: "verify_error",
                    detail: e.to_string(),
                };
            }
        };
        if !report.is_valid {
            let reason = classify_invalid(&report);
            tracing::warn!(event = "agent_refused", reason);
            return Decision::Refused {
                reason,
                detail: report.errors.join("; "),
            };
        }

        let version = report.version_count;
        if version != self.last_version {
            tracing::info!(
                event = "policy_updated",
                from = self.last_version,
                to = version
            );
            self.last_version = version;
        }

        let rules = match show_current_rules(&self.policy_path) {
            Ok(r) => r,
            Err(e) => {
                return Decision::Refused {
                    reason: "rules_unreadable",
                    detail: e.to_string(),
                };
            }
        };
        let policy = Policy::parse(&rules);

        if proposed == "unknown" {
            tracing::warn!(event = "agent_refused", reason = "llm_output_invalid");
            return Decision::Blocked {
                action: proposed,
                version,
                reason: "llm_output_invalid",
            };
        }
        if policy.permits(&proposed) {
            tracing::info!(event = "agent_decided", action = %proposed, version, decision = "execute");
            Decision::Executed {
                action: proposed,
                version,
            }
        } else {
            tracing::warn!(event = "agent_refused", reason = "not_in_allow_list");
            Decision::Blocked {
                action: proposed,
                version,
                reason: "not_in_allow_list",
            }
        }
    }
}

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

fn print_decision(idx: u64, ticket: &str, d: &Decision) {
    println!();
    println!("  ticket #{idx:02}  \"{ticket}\"");
    match d {
        Decision::Executed { action, version } => {
            println!("              v{version}  decision=EXECUTE  action={action}");
        }
        Decision::Blocked {
            action,
            version,
            reason,
        } => {
            println!(
                "              v{version}  decision=BLOCK    action={action}  reason={reason}"
            );
        }
        Decision::Refused { reason, detail } => {
            println!("                    decision=REFUSE   reason={reason}  ({detail})");
        }
    }
}

fn run_phase(agent: &mut Agent, label: &str, decision_log: Option<&DecisionLog>) {
    println!();
    println!("─── {label} ───────────────────────────────────────────────");
    for ticket in TICKETS {
        let d = agent.handle(ticket);
        print_decision(agent.tick_seq, ticket, &d);
        if let Some(log) = decision_log {
            log.append(agent.tick_seq, ticket, &d);
        }
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

fn banner(title: &str) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║ {title:<69} ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝");
}

#[derive(Debug, Default)]
struct Args {
    keep_policy: bool,
    decision_log: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--keep-policy" => args.keep_policy = true,
            "--decision-log" => match iter.next() {
                Some(p) => args.decision_log = Some(PathBuf::from(p)),
                None => return Err("--decision-log requires a path argument".to_string()),
            },
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

fn print_help() {
    println!("llm_policy_agent — Claude proposes, .aion policy gates");
    println!();
    println!("USAGE:");
    println!("  llm_policy_agent [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --keep-policy           Do not delete the policy file at exit (so");
    println!("                          you can run `aion show signatures` etc. on it)");
    println!("  --decision-log <PATH>   Append one JSON line per decision to PATH");
    println!("                          (NDJSON format, suitable for ingest)");
    println!("  -h, --help              Show this help");
    println!();
    println!("ENVIRONMENT:");
    println!("  ANTHROPIC_API_KEY       Required unless LLM_POLICY_NO_NETWORK=1");
    println!("  LLM_POLICY_NO_NETWORK   When non-empty, use the offline proposer");
    println!("  LLM_POLICY_MODEL        Override the Claude model name");
    println!("  AION_LOG                tracing level (default: warn)");
}

/// Append-only NDJSON decision-log sink. Each line is one decision
/// record with bounded fields suitable for log-store ingest.
struct DecisionLog {
    path: PathBuf,
}

impl DecisionLog {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn append(&self, tick: u64, ticket: &str, decision: &Decision) {
        let json = decision_record_json(tick, ticket, decision);
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "warning: failed to open decision log {}: {e}",
                    self.path.display()
                );
                return;
            }
        };
        if let Err(e) = writeln!(file, "{json}") {
            eprintln!(
                "warning: failed to write decision log {}: {e}",
                self.path.display()
            );
        }
    }
}

fn decision_record_json(tick: u64, ticket: &str, decision: &Decision) -> String {
    let (verdict, action, version, reason): (&str, String, Option<u64>, Option<&str>) =
        match decision {
            Decision::Executed { action, version } => {
                ("execute", action.clone(), Some(*version), None)
            }
            Decision::Blocked {
                action,
                version,
                reason,
            } => ("block", action.clone(), Some(*version), Some(*reason)),
            Decision::Refused { reason, .. } => ("refuse", String::new(), None, Some(*reason)),
        };
    let value = serde_json::json!({
        "tick": tick,
        "ticket_hash": short_hex_blake3(ticket.as_bytes()),
        "decision": verdict,
        "action": action,
        "version": version,
        "reason": reason,
    });
    value.to_string()
}

fn short_hex_blake3(bytes: &[u8]) -> String {
    let h = aion_context::crypto::hash(bytes);
    hex::encode(&h[..8])
}

/// Phase 5: dump the .aion file's in-file audit trail.
///
/// This is the audit ledger the file maintains for itself —
/// CreateGenesis at v1, CommitVersion at v2 in this demo. It is
/// hash-chained inside the file and signed; tampering breaks
/// `aion verify`.
fn dump_audit_trail(path: &Path) {
    println!();
    println!("─── Phase 5 — in-file audit trail (hash-chained inside the .aion) ───");
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            println!("  error reading file: {e}");
            return;
        }
    };
    let parser = match AionParser::new(&bytes) {
        Ok(p) => p,
        Err(e) => {
            println!("  error parsing file: {e}");
            return;
        }
    };
    let count = parser.header().audit_trail_count;
    println!("  audit_trail_count = {count}");
    for i in 0..count {
        let entry = match parser.get_audit_entry(i as usize) {
            Ok(e) => e,
            Err(e) => {
                println!("    [#{i}] error: {e}");
                continue;
            }
        };
        let action = entry
            .action_code()
            .map(|a| match a {
                ActionCode::CreateGenesis => "CreateGenesis",
                ActionCode::CommitVersion => "CommitVersion",
                ActionCode::Verify => "Verify",
                ActionCode::Inspect => "Inspect",
            })
            .unwrap_or("Unknown");
        println!(
            "  #{i:02}  ts={}  author={}  action={action}  prev_hash={}",
            entry.timestamp(),
            entry.author_id().as_u64(),
            hex::encode(&entry.previous_hash()[..8])
        );
    }
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

    let llm = match LlmClient::from_env() {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!("hint: export ANTHROPIC_API_KEY=sk-ant-...");
            eprintln!("hint: or set LLM_POLICY_NO_NETWORK=1 to use the offline proposer");
            return ExitCode::from(2);
        }
    };

    let path = std::env::temp_dir().join("aion_llm_policy_demo.aion");
    let key = SigningKey::generate();
    let author = AuthorId::new(OPERATOR_AUTHOR);
    let decision_log = args.decision_log.clone().map(DecisionLog::new);

    banner("llm_policy_agent — Claude proposes, .aion policy gates");
    println!("  policy file:  {}", path.display());
    println!("  operator:     author {OPERATOR_AUTHOR}");
    println!(
        "  proposer:     {}",
        if llm.offline {
            "offline (LLM_POLICY_NO_NETWORK=1)".to_string()
        } else {
            format!("Anthropic API ({})", llm.model)
        }
    );
    if let Some(ref dl) = decision_log {
        println!(
            "  decision log: {} (NDJSON, append-only)",
            dl.path.display()
        );
    }
    if args.keep_policy {
        println!("  keep policy:  true (file will survive at exit)");
    }
    println!("  tracing:      AION_LOG=info to see structured emits on stderr");

    let registry = init_demo(&path, &key, author);
    let mut agent = Agent::new(path.clone(), registry, llm);

    println!();
    println!("Phase 1 — operator init: policy v1 (lenient — all 5 actions allowed)");
    run_phase(
        &mut agent,
        "Phase 2 — LLM proposes under v1",
        decision_log.as_ref(),
    );

    println!();
    println!("Phase 3 — operator commits v2 (only fetch_url allowed)");
    commit_tightened(&path, &key, author, &agent.registry);
    run_phase(
        &mut agent,
        "Phase 4 — same model, same prompts, tighter gate",
        decision_log.as_ref(),
    );

    dump_audit_trail(&path);

    println!();
    println!("✓ demo complete");
    if args.keep_policy {
        let registry_path = path.with_extension("registry.json");
        match agent.registry.to_trusted_json() {
            Ok(json) => {
                if let Err(e) = std::fs::write(&registry_path, json) {
                    eprintln!(
                        "warning: failed to write registry to {}: {e}",
                        registry_path.display()
                    );
                } else {
                    println!("  registry kept at:    {}", registry_path.display());
                }
            }
            Err(e) => eprintln!("warning: failed to serialize registry: {e}"),
        }
        println!("  policy file kept at: {}", path.display());
        println!(
            "  inspect with:  aion show --registry {} {} signatures",
            registry_path.display(),
            path.display()
        );
        println!(
            "  verify with:   aion verify --registry {} {}",
            registry_path.display(),
            path.display()
        );
    } else {
        let _ = std::fs::remove_file(&path);
    }
    ExitCode::SUCCESS
}
