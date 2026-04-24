//! AION v2 CLI - Versioned Truth Infrastructure for AI Systems
//!
//! Command-line interface for managing AION files with cryptographic verification.

use aion_context::compliance::{generate_compliance_report, ComplianceFramework, ReportFormat};
use aion_context::export::{export_file, ExportFormat};
use aion_context::keystore::KeyStore;
use aion_context::operations::{
    commit_version, commit_version_force_unregistered, init_file, show_current_rules,
    show_file_info, show_signatures, show_version_history, verify_file, CommitOptions, InitOptions,
};
use aion_context::types::AuthorId;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

/// AION v2 - Versioned Truth Infrastructure for AI Systems
///
/// Manage cryptographically-signed, versioned business context files.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new AION file
    Init(InitArgs),

    /// Commit a new version to an AION file
    Commit(CommitArgs),

    /// Verify the integrity and signatures of an AION file
    Verify(VerifyArgs),

    /// Show file contents and metadata
    Show(ShowArgs),

    /// Manage cryptographic keys
    Key(KeyArgs),

    /// Generate compliance reports
    Report(ReportArgs),

    /// Export file data to JSON/YAML/CSV
    Export(ExportArgs),

    /// Manage trusted key registries (RFC-0028 / RFC-0034)
    Registry(RegistryArgs),

    /// Seal, verify, and inspect signed model releases (RFC-0032)
    Release(ReleaseArgs),
}

#[derive(Args, Debug)]
struct InitArgs {
    /// Path to the AION file to create
    #[arg(value_name = "FILE")]
    path: PathBuf,

    /// Initial rules content (file path or stdin if omitted)
    #[arg(short, long, value_name = "RULES_FILE")]
    rules: Option<PathBuf>,

    /// Author ID for the genesis version
    #[arg(short, long, value_name = "AUTHOR_ID")]
    author: u64,

    /// Signing key ID from keystore
    #[arg(short, long, value_name = "KEY_ID")]
    key: String,

    /// Commit message for genesis version
    #[arg(short, long, value_name = "MESSAGE", default_value = "Genesis version")]
    message: String,

    /// Overwrite existing file
    #[arg(long)]
    force: bool,

    /// Disable encryption (not recommended for production)
    #[arg(long)]
    no_encryption: bool,
}

#[derive(Args, Debug)]
struct CommitArgs {
    /// Path to the AION file
    #[arg(value_name = "FILE")]
    path: PathBuf,

    /// New rules content (file path or stdin if omitted)
    #[arg(short, long, value_name = "RULES_FILE")]
    rules: Option<PathBuf>,

    /// Author ID for this version
    #[arg(short, long, value_name = "AUTHOR_ID")]
    author: u64,

    /// Signing key ID from keystore
    #[arg(short, long, value_name = "KEY_ID")]
    key: String,

    /// Commit message
    #[arg(short, long, value_name = "MESSAGE")]
    message: String,

    /// Path to a JSON registry file (RFC-0034). Required post-Phase-E:
    /// commit pre-verifies the existing signature chain through the
    /// registry-aware path before appending the new version.
    #[arg(long, value_name = "REGISTRY_FILE")]
    registry: PathBuf,

    /// Bypass the registry authz pre-check (issue #25). By default,
    /// commit refuses to write if the supplied `(author, signing key)`
    /// does not match an active registry epoch at the target version.
    /// Setting this flag writes the entry anyway and prints a loud
    /// warning to stderr. Intended for staged-rollout or
    /// offline-signer workflows where operators sign before the
    /// registry is updated; the resulting file will not pass
    /// `aion verify --registry` until the registry is updated.
    #[arg(long)]
    force_unregistered: bool,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Path to the AION file to verify
    #[arg(value_name = "FILE")]
    path: PathBuf,

    /// Output format for verification report
    #[arg(short, long, value_name = "FORMAT", default_value = "text")]
    format: OutputFormat,

    /// Verbose output showing all checks
    #[arg(short, long)]
    verbose: bool,

    /// Path to a JSON registry file pinning the master and operational keys
    /// for each expected author (RFC-0034). Required post-Phase-E — every
    /// signature is cross-checked against the active epoch for its signer
    /// at the signed version number.
    #[arg(long, value_name = "REGISTRY_FILE")]
    registry: PathBuf,
}

#[derive(Args, Debug)]
struct ShowArgs {
    /// Path to the AION file
    #[arg(value_name = "FILE")]
    path: PathBuf,

    /// What to show
    #[command(subcommand)]
    subcommand: ShowSubcommand,

    /// Output format
    #[arg(short, long, value_name = "FORMAT", default_value = "text")]
    format: OutputFormat,

    /// Path to a JSON registry file (RFC-0034). Required post-Phase-E
    /// by every subcommand that verifies signatures or summarises the
    /// file state (which internally runs verify).
    #[arg(long, value_name = "REGISTRY_FILE")]
    registry: PathBuf,
}

#[derive(Subcommand, Debug)]
enum ShowSubcommand {
    /// Show current rules content
    Rules,

    /// Show version history
    History,

    /// Show signatures with verification status
    Signatures,

    /// Show complete file information
    Info,
}

#[derive(Args, Debug)]
struct KeyArgs {
    #[command(subcommand)]
    subcommand: KeySubcommand,
}

#[derive(Subcommand, Debug)]
enum KeySubcommand {
    /// Generate a new signing key pair
    Generate {
        /// Key ID for storage
        #[arg(short, long, value_name = "KEY_ID")]
        id: String,

        /// Description for the key
        #[arg(short, long, value_name = "DESCRIPTION")]
        description: Option<String>,
    },

    /// List all stored keys
    List,

    /// Export a key (password-protected)
    Export {
        /// Key ID to export
        #[arg(value_name = "KEY_ID")]
        id: String,

        /// Output file path
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },

    /// Import a key
    Import {
        /// Input file path
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Key ID for storage
        #[arg(short, long, value_name = "KEY_ID")]
        id: String,
    },

    /// Delete a key from keystore
    Delete {
        /// Key ID to delete
        #[arg(value_name = "KEY_ID")]
        id: String,

        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Args, Debug)]
struct ReportArgs {
    /// Path to the AION file
    #[arg(value_name = "FILE")]
    path: PathBuf,

    /// Compliance framework
    #[arg(short, long, value_enum, default_value = "generic")]
    framework: FrameworkType,

    /// Output format
    #[arg(short = 'F', long, value_enum, default_value = "markdown")]
    format: ReportFormatType,

    /// Output file (stdout if omitted)
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Path to a JSON registry file (RFC-0034) used for the verify
    /// step that feeds the report.
    #[arg(long, value_name = "REGISTRY_FILE")]
    registry: PathBuf,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum FrameworkType {
    /// SOX (Sarbanes-Oxley)
    Sox,
    /// HIPAA
    Hipaa,
    /// GDPR
    Gdpr,
    /// Generic audit report
    Generic,
}

impl From<FrameworkType> for ComplianceFramework {
    fn from(ft: FrameworkType) -> Self {
        match ft {
            FrameworkType::Sox => Self::Sox,
            FrameworkType::Hipaa => Self::Hipaa,
            FrameworkType::Gdpr => Self::Gdpr,
            FrameworkType::Generic => Self::Generic,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ReportFormatType {
    /// Plain text
    Text,
    /// Markdown (default)
    Markdown,
    /// JSON
    Json,
}

impl From<ReportFormatType> for ReportFormat {
    fn from(rft: ReportFormatType) -> Self {
        match rft {
            ReportFormatType::Text => Self::Text,
            ReportFormatType::Markdown => Self::Markdown,
            ReportFormatType::Json => Self::Json,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
}

#[derive(Args, Debug)]
struct ExportArgs {
    /// Path to the AION file
    #[arg(value_name = "FILE")]
    path: PathBuf,

    /// Export format
    #[arg(short, long, value_enum, default_value = "json")]
    format: ExportFormatType,

    /// Path to a JSON registry file (RFC-0034) used for the
    /// verify step that feeds the export.
    #[arg(long, value_name = "REGISTRY_FILE")]
    registry: PathBuf,

    /// Output file (stdout if omitted)
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct RegistryArgs {
    #[command(subcommand)]
    subcommand: RegistrySubcommand,
}

#[derive(Subcommand, Debug)]
enum RegistrySubcommand {
    /// Pin an author to a keystore-held signing key.
    ///
    /// Writes a trusted-registry JSON file recognised by
    /// `aion verify --registry`, `aion show --registry`, and
    /// friends. If `--output` already exists, the author is
    /// appended to the existing registry.
    ///
    /// If `--master` is omitted, the operational key is pinned as
    /// both master and epoch 0. This is a convenience for single-
    /// key development and tests; production deployments should
    /// supply a distinct master key so rotations can be authorised.
    Pin {
        /// `AuthorId` (u64) that signs the AION file's versions.
        #[arg(long, value_name = "AUTHOR_ID")]
        author: u64,

        /// Keystore key ID whose verifying key pins this author's
        /// epoch 0 operational key.
        #[arg(long, value_name = "KEY_ID")]
        key: String,

        /// Optional keystore key ID whose verifying key becomes the
        /// master key for this author. Defaults to `--key`.
        #[arg(long, value_name = "MASTER_KEY_ID")]
        master: Option<String>,

        /// Output registry JSON file. If it exists, the author is
        /// appended in place.
        #[arg(short, long, value_name = "OUTPUT")]
        output: PathBuf,
    },

    /// Rotate an author's operational key (RFC-0028).
    ///
    /// Builds a master-signed rotation record and applies it to the
    /// supplied registry, minting a new epoch from
    /// `--effective-from-version` onward. The registry JSON file is
    /// updated in place via write-then-rename.
    Rotate {
        /// `AuthorId` whose key is being rotated.
        #[arg(long, value_name = "AUTHOR_ID")]
        author: u64,

        /// Currently-active epoch being rotated out. Must match the
        /// registry's current active epoch for this author.
        #[arg(long, value_name = "N")]
        from_epoch: u32,

        /// New epoch number. Must equal `from_epoch + 1`.
        #[arg(long, value_name = "N_PLUS_1")]
        to_epoch: u32,

        /// Keystore key ID whose verifying key becomes the epoch's
        /// new operational public key.
        #[arg(long, value_name = "KEY_ID")]
        new_key: String,

        /// Keystore key ID for the author's master key (must match
        /// the master key pinned at registration time; otherwise the
        /// rotation record fails to verify).
        #[arg(long, value_name = "MASTER_KEY_ID")]
        master_key: String,

        /// aion version number at which the rotation takes effect.
        /// Must be at or after the current active epoch's
        /// `created_at_version`.
        #[arg(long, value_name = "V")]
        effective_from_version: u64,

        /// Path to the registry JSON file to mutate in place.
        #[arg(long, value_name = "REGISTRY_FILE")]
        registry: PathBuf,
    },

    /// Revoke an author's epoch (RFC-0028).
    ///
    /// Builds a master-signed revocation record and applies it to the
    /// supplied registry. Signatures from the revoked epoch at or
    /// after `--effective-from-version` stop resolving; earlier
    /// signatures remain valid.
    Revoke {
        /// `AuthorId` whose epoch is being revoked.
        #[arg(long, value_name = "AUTHOR_ID")]
        author: u64,

        /// Epoch number to revoke.
        #[arg(long, value_name = "N")]
        epoch: u32,

        /// Reason code for the revocation record.
        #[arg(long, value_enum)]
        reason: CliRevocationReason,

        /// Keystore key ID for the author's master key.
        #[arg(long, value_name = "MASTER_KEY_ID")]
        master_key: String,

        /// aion version number at which the revocation takes effect.
        #[arg(long, value_name = "V")]
        effective_from_version: u64,

        /// Path to the registry JSON file to mutate in place.
        #[arg(long, value_name = "REGISTRY_FILE")]
        registry: PathBuf,
    },
}

/// CLI surface for [`aion_context::key_registry::RevocationReason`].
/// Kept distinct so clap remains out of the library.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum CliRevocationReason {
    /// Key material is known or suspected to be compromised.
    Compromised,
    /// Routine rotation; the prior key is not believed compromised.
    Superseded,
    /// Signer leaves the org; no successor epoch.
    Retired,
    /// Reason not recorded at protocol level.
    Unspecified,
}

impl From<CliRevocationReason> for aion_context::key_registry::RevocationReason {
    fn from(r: CliRevocationReason) -> Self {
        match r {
            CliRevocationReason::Compromised => Self::Compromised,
            CliRevocationReason::Superseded => Self::Superseded,
            CliRevocationReason::Retired => Self::Retired,
            CliRevocationReason::Unspecified => Self::Unspecified,
        }
    }
}

#[derive(Args, Debug)]
struct ReleaseArgs {
    #[command(subcommand)]
    subcommand: ReleaseSubcommand,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)] // Seal carries many CLI fields; other variants are small — CLI-scoped
enum ReleaseSubcommand {
    /// Seal a signed release (RFC-0032).
    ///
    /// Composes the primary artifact + frameworks + licenses + safety
    /// attestations + export controls + builder.id into a
    /// [`ReleaseBuilder`] and calls `.seal(...)`. Writes a single
    /// `release.json` bundle plus the primary artifact as
    /// `primary.bin` under `--out-dir`.
    Seal {
        /// Path to the primary artifact bytes (e.g. model.safetensors).
        #[arg(long, value_name = "PATH")]
        primary: PathBuf,

        /// In-manifest name for the primary artifact.
        #[arg(long, value_name = "NAME")]
        primary_name: String,

        /// Model name (in the AIBOM and OCI manifests).
        #[arg(long, value_name = "NAME")]
        model_name: String,

        /// Model version string.
        #[arg(long, value_name = "VERSION")]
        model_version: String,

        /// Serialisation format — `safetensors` / `gguf` / `onnx` / ...
        #[arg(long, value_name = "FORMAT", default_value = "safetensors")]
        model_format: String,

        /// Framework dependency in `name:version` form. Repeatable.
        #[arg(long, value_name = "NAME:VERSION")]
        framework: Vec<String>,

        /// License in `spdx_id:scope` form (scope =
        /// `weights`|`source`|`data`|`docs`|`combined`). Repeatable.
        #[arg(long, value_name = "SPDX:SCOPE")]
        license: Vec<String>,

        /// Safety attestation in `name:result` form. Repeatable.
        #[arg(long, value_name = "NAME:RESULT")]
        safety_attestation: Vec<String>,

        /// Export-control entry in `regime:classification` form.
        #[arg(long, value_name = "REGIME:CLASS")]
        export_control: Vec<String>,

        /// SLSA `builder.id` URI.
        #[arg(long, value_name = "URI")]
        builder_id: String,

        /// Current aion version number at seal time.
        #[arg(long, value_name = "N", default_value_t = 1u64)]
        aion_version: u64,

        /// Signer's `AuthorId`.
        #[arg(long, value_name = "AUTHOR_ID")]
        author: u64,

        /// Signer's operational key ID in the keystore.
        #[arg(long, value_name = "KEY_ID")]
        key: String,

        /// Output directory for the sealed bundle.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,
    },

    /// Verify a previously-sealed release bundle.
    ///
    /// Reloads the bundle and the primary artifact from
    /// `--bundle`, reconstructs a [`SignedRelease`] via
    /// `SignedRelease::from_components`, and calls
    /// `.verify(&registry, at_version)`. Exit 0 when valid; exit 1
    /// when any component fails (mirrors #23 exit-code contract).
    Verify {
        /// Directory produced by `aion release seal`.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,

        /// Trusted-registry JSON file (RFC-0028) pinning the signer.
        #[arg(long, value_name = "REGISTRY_FILE")]
        registry: PathBuf,

        /// aion version number to resolve registry epochs at.
        #[arg(long, value_name = "N", default_value_t = 1u64)]
        at_version: u64,
    },

    /// Pretty-print a bundle summary (no crypto verification).
    Inspect {
        /// Directory produced by `aion release seal`.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,

        /// Output format.
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ExportFormatType {
    /// JSON format (full metadata)
    Json,
    /// YAML format (human-readable)
    Yaml,
    /// CSV format (audit trail only)
    Csv,
}

impl From<ExportFormatType> for ExportFormat {
    fn from(eft: ExportFormatType) -> Self {
        match eft {
            ExportFormatType::Json => Self::Json,
            ExportFormatType::Yaml => Self::Yaml,
            ExportFormatType::Csv => Self::Csv,
        }
    }
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init(args) => cmd_init(&args),
        Commands::Commit(args) => cmd_commit(&args),
        Commands::Verify(args) => cmd_verify(&args),
        Commands::Show(args) => cmd_show(&args),
        Commands::Key(args) => cmd_key(&args),
        Commands::Report(args) => cmd_report(&args),
        Commands::Export(args) => cmd_export(&args),
        Commands::Registry(args) => cmd_registry(&args),
        Commands::Release(args) => cmd_release(&args),
    }
}

fn cmd_init(args: &InitArgs) -> Result<ExitCode> {
    print_init_banner(args);
    if args.path.exists() && !args.force {
        anyhow::bail!(
            "File already exists: {}\nUse --force to overwrite",
            args.path.display()
        );
    }
    let rules = load_rules_content(args.rules.as_ref())?;
    println!("   Rules size: {} bytes", rules.len());

    let signing_key = load_signing_key_for_init(args)?;
    let options = InitOptions {
        author_id: AuthorId::new(args.author),
        signing_key: &signing_key,
        message: &args.message,
        timestamp: None,
    };
    if args.force && args.path.exists() {
        std::fs::remove_file(&args.path)
            .with_context(|| format!("Failed to remove existing file: {}", args.path.display()))?;
    }
    let result = init_file(&args.path, &rules, &options)
        .with_context(|| format!("Failed to create AION file: {}", args.path.display()))?;
    println!("\n✅ File created successfully!");
    println!("   File ID: 0x{:016x}", result.file_id.as_u64());
    println!("   Version: {}", result.version.as_u64());
    println!("   Path: {}", args.path.display());
    Ok(ExitCode::SUCCESS)
}

fn print_init_banner(args: &InitArgs) {
    println!("🚀 Initializing AION file: {}", args.path.display());
    println!("   Author: {}", args.author);
    println!("   Message: {}", args.message);
    println!(
        "   Encryption: {}",
        if args.no_encryption {
            "disabled"
        } else {
            "enabled"
        }
    );
}

fn load_signing_key_for_init(args: &InitArgs) -> Result<aion_context::crypto::SigningKey> {
    let keystore = KeyStore::new();
    let key_author_id = parse_key_id(&args.key)?;
    keystore.load_signing_key(key_author_id).with_context(|| {
        format!(
            "Failed to load key '{}' from keystore.\n\
            Hint: Generate a key first with: aion key generate --id {}",
            args.key, args.key
        )
    })
}

fn cmd_commit(args: &CommitArgs) -> Result<ExitCode> {
    println!("📝 Committing new version to: {}", args.path.display());
    println!("   Author: {}", args.author);
    println!("   Message: {}", args.message);

    // Check if file exists
    if !args.path.exists() {
        anyhow::bail!("File not found: {}", args.path.display());
    }

    // Load new rules from file or stdin
    let rules = load_rules_content(args.rules.as_ref())?;
    println!("   New rules size: {} bytes", rules.len());

    // Load signing key from keystore
    let keystore = KeyStore::new();
    let key_author_id = parse_key_id(&args.key)?;

    let signing_key = keystore.load_signing_key(key_author_id).with_context(|| {
        format!(
            "Failed to load key '{}' from keystore.\n\
            Hint: Generate a key first with: aion key generate --id {}",
            args.key, args.key
        )
    })?;

    // Create commit options
    let options = CommitOptions {
        author_id: AuthorId::new(args.author),
        signing_key: &signing_key,
        message: &args.message,
        timestamp: None, // Use current time
    };

    // Commit the new version
    let registry = load_registry_from_path(&args.registry)?;
    let result = if args.force_unregistered {
        eprintln!(
            "⚠️  --force-unregistered: skipping registry authz pre-check. \
             The resulting file will NOT pass `aion verify --registry` until \
             the registry is updated to pin this signer (issue #25)."
        );
        commit_version_force_unregistered(&args.path, &rules, &options, &registry)
            .with_context(|| format!("Failed to commit new version to: {}", args.path.display()))?
    } else {
        commit_version(&args.path, &rules, &options, &registry)
            .with_context(|| format!("Failed to commit new version to: {}", args.path.display()))?
    };

    println!("\n✅ Version committed successfully!");
    println!("   New version: {}", result.version.as_u64());
    println!("   Rules hash: {}", hex::encode(result.rules_hash));
    println!("   Path: {}", args.path.display());

    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(args: &VerifyArgs) -> Result<ExitCode> {
    println!("🔍 Verifying AION file: {}", args.path.display());
    if !args.path.exists() {
        anyhow::bail!("File not found: {}", args.path.display());
    }
    let registry = load_registry_from_path(&args.registry)?;
    println!(
        "   Registry: {} (registry-aware verify)",
        args.registry.to_str().unwrap_or("<invalid path>")
    );
    let report = verify_file(&args.path, &registry)
        .with_context(|| format!("Failed to verify file: {}", args.path.display()))?;

    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&report)?),
        OutputFormat::Text => print_verify_text_report(args, &report),
    }

    Ok(report.exit_code())
}

fn load_registry_from_path(
    path: &std::path::Path,
) -> Result<aion_context::key_registry::KeyRegistry> {
    let bytes = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read registry file: {}", path.display()))?;
    aion_context::key_registry::KeyRegistry::from_trusted_json(&bytes)
        .with_context(|| format!("Failed to parse registry file: {}", path.display()))
}

fn print_verify_text_report(
    args: &VerifyArgs,
    report: &aion_context::operations::VerificationReport,
) {
    println!("\nVerification Results:");
    println!("====================");
    println!(
        "Overall: {}",
        if report.is_valid {
            "✅ VALID"
        } else {
            "❌ INVALID"
        }
    );
    println!();
    println!(
        "Structure:     {}",
        if report.structure_valid { "✅" } else { "❌" }
    );
    println!(
        "Integrity:     {}",
        if report.integrity_hash_valid {
            "✅"
        } else {
            "❌"
        }
    );
    println!(
        "Hash Chain:    {}",
        if report.hash_chain_valid {
            "✅"
        } else {
            "❌"
        }
    );
    println!(
        "Signatures:    {}",
        if report.signatures_valid {
            "✅"
        } else {
            "❌"
        }
    );
    if !report.errors.is_empty() {
        println!("\nErrors:");
        for error in &report.errors {
            println!("  • {error}");
        }
    }
    if args.verbose {
        println!("\nFile Path: {}", args.path.display());
    }
}

fn cmd_show(args: &ShowArgs) -> Result<ExitCode> {
    // Check if file exists
    if !args.path.exists() {
        anyhow::bail!("File not found: {}", args.path.display());
    }

    match &args.subcommand {
        ShowSubcommand::Rules => show_rules_subcommand(args)?,
        ShowSubcommand::History => show_history_subcommand(args)?,
        ShowSubcommand::Signatures => show_signatures_subcommand(args)?,
        ShowSubcommand::Info => show_info_subcommand(args)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn show_rules_subcommand(args: &ShowArgs) -> Result<()> {
    let rules = show_current_rules(&args.path)?;
    match args.format {
        OutputFormat::Json | OutputFormat::Yaml => println!("{}", hex::encode(&rules)),
        OutputFormat::Text => {
            if let Ok(text) = std::str::from_utf8(&rules) {
                println!("{text}");
            } else {
                eprintln!("⚠️  Rules contain binary data, displaying as hex:");
                println!("{}", hex::encode(&rules));
            }
        }
    }
    Ok(())
}

fn show_history_subcommand(args: &ShowArgs) -> Result<()> {
    let versions = show_version_history(&args.path)?;
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&versions)?),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&versions)?),
        OutputFormat::Text => {
            println!("Version History ({} versions)", versions.len());
            println!("================================\n");
            for v in &versions {
                println!("Version {}:", v.version_number);
                println!("  Author:    {}", v.author_id);
                println!("  Timestamp: {}", v.timestamp);
                println!("  Message:   {}", v.message);
                println!("  Rules Hash: {}", hex::encode(v.rules_hash));
                if let Some(parent) = v.parent_hash {
                    println!("  Parent Hash: {}", hex::encode(parent));
                }
                println!();
            }
        }
    }
    Ok(())
}

fn show_signatures_subcommand(args: &ShowArgs) -> Result<()> {
    let registry = load_registry_from_path(&args.registry)?;
    let signatures = show_signatures(&args.path, &registry)?;
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&signatures)?),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&signatures)?),
        OutputFormat::Text => {
            println!("Signatures ({} total)", signatures.len());
            println!("==================\n");
            for sig in &signatures {
                let status = if sig.verified {
                    "✅ VALID"
                } else {
                    "❌ INVALID"
                };
                println!("Version {}: {status}", sig.version_number);
                println!("  Author: {}", sig.author_id);
                println!("  Public Key: {}", hex::encode(sig.public_key));
                if let Some(error) = &sig.error {
                    println!("  Error: {error}");
                }
                println!();
            }
        }
    }
    Ok(())
}

fn show_info_subcommand(args: &ShowArgs) -> Result<()> {
    let registry = load_registry_from_path(&args.registry)?;
    let info = show_file_info(&args.path, &registry)?;
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&info)?),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&info)?),
        OutputFormat::Text => {
            println!("File Information");
            println!("================");
            println!("File ID:         0x{:016x}", info.file_id);
            println!("Current Version: {}", info.current_version);
            println!("Total Versions:  {}", info.version_count);
            println!("\nLatest Version:");
            if let Some(latest) = info.versions.last() {
                println!("  Number:   {}", latest.version_number);
                println!("  Author:   {}", latest.author_id);
                println!("  Timestamp: {}", latest.timestamp);
                println!("  Message:  {}", latest.message);
            }
            println!("\nSignature Status:");
            let valid_count = info.signatures.iter().filter(|s| s.verified).count();
            println!("  Valid: {valid_count}/{}", info.signatures.len());
        }
    }
    Ok(())
}

fn cmd_key(args: &KeyArgs) -> Result<ExitCode> {
    let keystore = KeyStore::new();

    match &args.subcommand {
        KeySubcommand::Generate { id, description } => {
            cmd_key_generate(&keystore, id, description.as_deref())?;
        }
        KeySubcommand::List => cmd_key_list(&keystore)?,
        KeySubcommand::Export { id, output } => cmd_key_export(&keystore, id, output)?,
        KeySubcommand::Import { path, id } => cmd_key_import(&keystore, path, id)?,
        KeySubcommand::Delete { id, force } => cmd_key_delete(&keystore, id, *force)?,
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_key_generate(keystore: &KeyStore, key_id: &str, description: Option<&str>) -> Result<()> {
    println!("🔑 Generating new signing key...");

    // Parse key ID as author ID
    let author_id = parse_key_id(key_id)?;

    // Check if key already exists
    if keystore.has_signing_key(author_id) {
        anyhow::bail!(
            "Key already exists for author ID {key_id}\nUse 'aion key delete {key_id}' first or choose a different ID"
        );
    }

    // Generate keypair
    let (_, verifying_key) = keystore
        .generate_keypair(author_id)
        .context("Failed to generate keypair")?;

    println!("\n✅ Key generated successfully!");
    println!("   Key ID: {key_id}");
    println!("   Author ID: {}", author_id.as_u64());
    println!("   Public Key: {}", hex::encode(verifying_key.to_bytes()));

    if let Some(desc) = description {
        println!("   Description: {desc}");
    }

    println!("\n💡 Key stored securely in OS keyring");
    println!("   Use 'aion key export {key_id}' to create a backup");

    Ok(())
}

fn cmd_key_list(keystore: &KeyStore) -> Result<()> {
    println!("🔑 Stored Keys");
    println!("=============\n");

    // Get list of stored keys
    let keys = keystore.list_keys()?;

    if keys.is_empty() {
        // For file-based storage, list_keys works
        // For keyring, we need to scan (keyring doesn't support enumeration)
        let mut found_any = false;

        // Try scanning common ID ranges for keyring-based storage
        for id in 1..10000 {
            let author_id = AuthorId::new(id);
            if keystore.has_signing_key(author_id) {
                found_any = true;
                let signing_key = keystore.load_signing_key(author_id)?;
                let verifying_key = signing_key.verifying_key();

                println!("Key ID: {id}");
                println!("  Author ID: {id}");
                println!("  Public Key: {}", hex::encode(verifying_key.to_bytes()));
                println!();
            }
        }

        if !found_any {
            println!("No keys found in keystore.");
            println!("\n💡 Generate a new key with: aion key generate <KEY_ID>");
        }
    } else {
        // File-based storage - we have the full list
        let count = keys.len();
        for author_id in keys {
            let signing_key = keystore.load_signing_key(author_id)?;
            let verifying_key = signing_key.verifying_key();
            let id = author_id.as_u64();

            println!("Key ID: {id}");
            println!("  Author ID: {id}");
            println!("  Public Key: {}", hex::encode(verifying_key.to_bytes()));
            println!();
        }

        println!("Total: {count} key(s)");
    }

    Ok(())
}

fn cmd_key_export(keystore: &KeyStore, key_id: &str, output: &PathBuf) -> Result<()> {
    println!("🔐 Exporting key {key_id}...");

    // Parse key ID
    let author_id = parse_key_id(key_id)?;

    // Check if key exists
    if !keystore.has_signing_key(author_id) {
        anyhow::bail!("Key not found: {key_id}\nUse 'aion key list' to see available keys");
    }

    // Get password from user
    let password = rpassword::prompt_password("Enter password for encryption: ")
        .context("Failed to read password")?;

    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    let confirm = rpassword::prompt_password("Confirm password: ")
        .context("Failed to read password confirmation")?;

    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    // Export key with encryption
    let encrypted_bytes = keystore
        .export_encrypted(author_id, &password)
        .context("Failed to export key")?;

    // Write to file
    std::fs::write(output, encrypted_bytes)
        .with_context(|| format!("Failed to write to: {}", output.display()))?;

    println!("\n✅ Key exported successfully!");
    println!("   Output: {}", output.display());
    println!("   Size: {} bytes", std::fs::metadata(output)?.len());
    println!("\n⚠️  Keep this file secure - it contains your private key!");

    Ok(())
}

fn cmd_key_import(keystore: &KeyStore, path: &PathBuf, key_id: &str) -> Result<()> {
    println!("🔓 Importing key from {}...", path.display());

    // Parse key ID
    let author_id = parse_key_id(key_id)?;

    // Check if key already exists
    if keystore.has_signing_key(author_id) {
        anyhow::bail!(
            "Key already exists for author ID {key_id}\nUse 'aion key delete {key_id}' first"
        );
    }

    // Read encrypted file
    let encrypted_bytes =
        std::fs::read(path).with_context(|| format!("Failed to read from: {}", path.display()))?;

    // Get password from user
    let password =
        rpassword::prompt_password("Enter password: ").context("Failed to read password")?;

    // Import key
    keystore
        .import_encrypted(author_id, &password, &encrypted_bytes)
        .context("Failed to import key (wrong password or corrupted file)")?;

    // Load to display public key
    let signing_key = keystore.load_signing_key(author_id)?;
    let verifying_key = signing_key.verifying_key();

    println!("\n✅ Key imported successfully!");
    println!("   Key ID: {key_id}");
    println!("   Author ID: {}", author_id.as_u64());
    println!("   Public Key: {}", hex::encode(verifying_key.to_bytes()));
    println!("\n💡 Key stored securely in OS keyring");

    Ok(())
}

fn cmd_key_delete(keystore: &KeyStore, key_id: &str, force: bool) -> Result<()> {
    // Parse key ID
    let author_id = parse_key_id(key_id)?;

    // Check if key exists
    if !keystore.has_signing_key(author_id) {
        anyhow::bail!("Key not found: {key_id}\nUse 'aion key list' to see available keys");
    }

    // Confirmation prompt unless --force
    if !force {
        print!("⚠️  Are you sure you want to delete key {key_id}? This cannot be undone. (y/N): ");
        std::io::stdout().flush()?;

        let mut response = String::new();
        std::io::stdin().read_line(&mut response)?;

        if !response.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Delete key
    keystore
        .delete_signing_key(author_id)
        .context("Failed to delete key")?;

    println!("✅ Key {key_id} deleted from keystore");

    Ok(())
}

/// Parse key ID string to `AuthorId`
fn parse_key_id(key_id: &str) -> Result<AuthorId> {
    let id = key_id
        .parse::<u64>()
        .with_context(|| format!("Invalid key ID '{key_id}': must be a number"))?;
    Ok(AuthorId::new(id))
}

/// Load rules content from a file path or stdin
fn load_rules_content(path: Option<&PathBuf>) -> Result<Vec<u8>> {
    if let Some(file_path) = path {
        std::fs::read(file_path).with_context(|| {
            format!(
                "Failed to read rules from: {file_path}",
                file_path = file_path.display()
            )
        })
    } else {
        // Read from stdin
        let mut buffer = Vec::new();
        io::stdin()
            .read_to_end(&mut buffer)
            .context("Failed to read rules from stdin")?;
        Ok(buffer)
    }
}

// ============================================================================
// Compliance Reporting Command
// ============================================================================

fn cmd_report(args: &ReportArgs) -> Result<ExitCode> {
    let framework: ComplianceFramework = args.framework.into();
    let format: ReportFormat = args.format.into();

    eprintln!(
        "📊 Generating {} report for: {}",
        framework,
        args.path.display()
    );
    eprintln!("   Format: {:?}", args.format);

    // Generate the report
    let registry = load_registry_from_path(&args.registry)?;
    let report = generate_compliance_report(&args.path, framework, format, &registry)
        .context("Failed to generate compliance report")?;

    // Output to file or stdout
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &report)
            .with_context(|| format!("Failed to write report to: {}", output_path.display()))?;
        eprintln!("✅ Report saved to: {}", output_path.display());
    } else {
        println!("{report}");
    }

    Ok(ExitCode::SUCCESS)
}

// ============================================================================
// Export Command
// ============================================================================

fn cmd_export(args: &ExportArgs) -> Result<ExitCode> {
    let format: ExportFormat = args.format.into();

    eprintln!(
        "📤 Exporting {} from: {}",
        format_name(args.format),
        args.path.display()
    );

    let registry = load_registry_from_path(&args.registry)?;
    let output = export_file(&args.path, format, &registry).context("Failed to export file")?;

    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &output)
            .with_context(|| format!("Failed to write export to: {}", output_path.display()))?;
        eprintln!("✅ Exported to: {}", output_path.display());
    } else {
        println!("{output}");
    }

    Ok(ExitCode::SUCCESS)
}

const fn format_name(format: ExportFormatType) -> &'static str {
    match format {
        ExportFormatType::Json => "JSON",
        ExportFormatType::Yaml => "YAML",
        ExportFormatType::Csv => "CSV",
    }
}

fn cmd_registry(args: &RegistryArgs) -> Result<ExitCode> {
    match &args.subcommand {
        RegistrySubcommand::Pin {
            author,
            key,
            master,
            output,
        } => cmd_registry_pin(*author, key, master.as_deref(), output)?,
        RegistrySubcommand::Rotate {
            author,
            from_epoch,
            to_epoch,
            new_key,
            master_key,
            effective_from_version,
            registry,
        } => cmd_registry_rotate(
            *author,
            *from_epoch,
            *to_epoch,
            new_key,
            master_key,
            *effective_from_version,
            registry,
        )?,
        RegistrySubcommand::Revoke {
            author,
            epoch,
            reason,
            master_key,
            effective_from_version,
            registry,
        } => cmd_registry_revoke(
            *author,
            *epoch,
            (*reason).into(),
            master_key,
            *effective_from_version,
            registry,
        )?,
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_registry_pin(
    author: u64,
    key_id: &str,
    master_key_id: Option<&str>,
    output: &std::path::Path,
) -> Result<()> {
    let keystore = KeyStore::new();
    let op_signer = load_key_for_registry(&keystore, key_id)?;
    let master_signer = match master_key_id {
        Some(id) => load_key_for_registry(&keystore, id)?,
        None => op_signer.clone(),
    };

    let author_id = AuthorId::new(author);
    let mut registry = load_or_new_registry(output)?;
    registry
        .register_author(
            author_id,
            master_signer.verifying_key(),
            op_signer.verifying_key(),
            0,
        )
        .with_context(|| format!("Failed to pin author {author}"))?;

    write_registry_atomic(&registry, output)?;

    println!("✅ Pinned author {author} with key '{key_id}'");
    println!("   Registry: {}", output.display());
    Ok(())
}

fn cmd_registry_rotate(
    author: u64,
    from_epoch: u32,
    to_epoch: u32,
    new_key_id: &str,
    master_key_id: &str,
    effective_from_version: u64,
    registry_path: &std::path::Path,
) -> Result<()> {
    let keystore = KeyStore::new();
    let new_op = load_key_for_registry(&keystore, new_key_id)?;
    let master = load_key_for_registry(&keystore, master_key_id)?;

    let mut registry = load_existing_registry(registry_path)?;
    let record = aion_context::key_registry::sign_rotation_record(
        AuthorId::new(author),
        from_epoch,
        to_epoch,
        new_op.verifying_key().to_bytes(),
        effective_from_version,
        &master,
    );
    registry.apply_rotation(&record).with_context(|| {
        format!(
            "Failed to apply rotation for author {author} (from epoch {from_epoch} \
             to epoch {to_epoch} effective version {effective_from_version})"
        )
    })?;

    write_registry_atomic(&registry, registry_path)?;

    println!(
        "✅ Rotated author {author}: epoch {from_epoch} → {to_epoch}, effective from version {effective_from_version}"
    );
    println!("   Registry: {}", registry_path.display());
    Ok(())
}

fn cmd_registry_revoke(
    author: u64,
    epoch: u32,
    reason: aion_context::key_registry::RevocationReason,
    master_key_id: &str,
    effective_from_version: u64,
    registry_path: &std::path::Path,
) -> Result<()> {
    let keystore = KeyStore::new();
    let master = load_key_for_registry(&keystore, master_key_id)?;

    let mut registry = load_existing_registry(registry_path)?;
    let record = aion_context::key_registry::sign_revocation_record(
        AuthorId::new(author),
        epoch,
        reason,
        effective_from_version,
        &master,
    );
    registry.apply_revocation(&record).with_context(|| {
        format!(
            "Failed to apply revocation for author {author} epoch {epoch} \
             effective version {effective_from_version}"
        )
    })?;

    write_registry_atomic(&registry, registry_path)?;

    println!(
        "✅ Revoked author {author} epoch {epoch} ({reason:?}), effective from version {effective_from_version}"
    );
    println!("   Registry: {}", registry_path.display());
    Ok(())
}

fn load_existing_registry(
    path: &std::path::Path,
) -> Result<aion_context::key_registry::KeyRegistry> {
    if !path.exists() {
        anyhow::bail!(
            "Registry file not found: {}\n\
             Hint: use `aion registry pin` first to create one.",
            path.display()
        );
    }
    let bytes = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read registry file: {}", path.display()))?;
    aion_context::key_registry::KeyRegistry::from_trusted_json(&bytes)
        .with_context(|| format!("Failed to parse registry file: {}", path.display()))
}

fn load_or_new_registry(path: &std::path::Path) -> Result<aion_context::key_registry::KeyRegistry> {
    if path.exists() {
        load_existing_registry(path)
    } else {
        Ok(aion_context::key_registry::KeyRegistry::new())
    }
}

/// Write a registry to disk atomically: serialise, write to a sibling
/// `.tmp` file, fsync if possible, then rename over the target. A
/// crash at any point leaves either the old file or the new file in
/// place — never a half-written one.
fn write_registry_atomic(
    registry: &aion_context::key_registry::KeyRegistry,
    path: &std::path::Path,
) -> Result<()> {
    let json = registry
        .to_trusted_json()
        .context("Failed to serialize registry")?;
    let mut tmp = path.to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("registry.json");
    tmp.set_file_name(format!(".{file_name}.tmp"));
    std::fs::write(&tmp, &json)
        .with_context(|| format!("Failed to write staging file: {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to rename into place: {}", path.display()))?;
    Ok(())
}

fn load_key_for_registry(
    keystore: &KeyStore,
    key_id: &str,
) -> Result<aion_context::crypto::SigningKey> {
    let parsed_id = parse_key_id(key_id)?;
    keystore
        .load_signing_key(parsed_id)
        .with_context(|| format!("Failed to load key '{key_id}' from keystore"))
}

// ============================================================================
// Release subcommand (issue #28) — sealed-release bundle format + handlers.
// ============================================================================

/// On-disk JSON bundle representing a complete [`aion_context::release::SignedRelease`].
///
/// Most components have serde derives and serialize directly. The
/// three zerocopy types — `ArtifactManifest`, `SignatureEntry`, and
/// `LogSeq` — are lowered to simpler JSON shapes here: manifest as
/// hex-encoded canonical bytes, signature as per-field hex strings,
/// log sequence as `(kind_u16, seq)` tuples.
#[derive(serde::Serialize, serde::Deserialize)]
struct ReleaseBundle {
    signer: u64,
    model_ref: aion_context::aibom::ModelRef,
    manifest_canonical_hex: String,
    manifest_signature: BundleSig,
    manifest_dsse: aion_context::dsse::DsseEnvelope,
    aibom: aion_context::aibom::AiBom,
    aibom_dsse: aion_context::dsse::DsseEnvelope,
    slsa_statement: aion_context::slsa::InTotoStatement,
    slsa_dsse: aion_context::dsse::DsseEnvelope,
    oci_primary: aion_context::oci::OciArtifactManifest,
    oci_aibom_referrer: aion_context::oci::OciArtifactManifest,
    oci_slsa_referrer: aion_context::oci::OciArtifactManifest,
    log_entries: Vec<BundleLogSeq>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BundleSig {
    author_id: u64,
    public_key_hex: String,
    signature_hex: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BundleLogSeq {
    kind: u16,
    seq: u64,
}

fn cmd_release(args: &ReleaseArgs) -> Result<ExitCode> {
    match &args.subcommand {
        ReleaseSubcommand::Seal {
            primary,
            primary_name,
            model_name,
            model_version,
            model_format,
            framework,
            license,
            safety_attestation,
            export_control,
            builder_id,
            aion_version,
            author,
            key,
            out_dir,
        } => cmd_release_seal(SealInputs {
            primary,
            primary_name,
            model_name,
            model_version,
            model_format,
            framework,
            license,
            safety_attestation,
            export_control,
            builder_id,
            aion_version: *aion_version,
            author: *author,
            key,
            out_dir,
        })?,
        ReleaseSubcommand::Verify {
            bundle,
            registry,
            at_version,
        } => return cmd_release_verify(bundle, registry, *at_version),
        ReleaseSubcommand::Inspect { bundle, format } => cmd_release_inspect(bundle, *format)?,
    }
    Ok(ExitCode::SUCCESS)
}

struct SealInputs<'a> {
    primary: &'a PathBuf,
    primary_name: &'a str,
    model_name: &'a str,
    model_version: &'a str,
    model_format: &'a str,
    framework: &'a [String],
    license: &'a [String],
    safety_attestation: &'a [String],
    export_control: &'a [String],
    builder_id: &'a str,
    aion_version: u64,
    author: u64,
    key: &'a str,
    out_dir: &'a PathBuf,
}

#[allow(clippy::needless_pass_by_value)] // SealInputs is a by-value bag of &str/&[String] — fine to consume
fn cmd_release_seal(inp: SealInputs<'_>) -> Result<()> {
    use aion_context::aibom::{ExportControl, FrameworkRef, License, SafetyAttestation};
    use aion_context::release::ReleaseBuilder;
    use aion_context::transparency_log::TransparencyLog;
    use aion_context::types::AuthorId;

    let primary_bytes = std::fs::read(inp.primary)
        .with_context(|| format!("Failed to read primary artifact: {}", inp.primary.display()))?;
    println!("📦 Sealing {} v{}", inp.model_name, inp.model_version);
    println!(
        "   Primary: {} ({} bytes)",
        inp.primary_name,
        primary_bytes.len()
    );

    let keystore = KeyStore::new();
    let signing_key = load_key_for_registry(&keystore, inp.key)?;

    let mut builder = ReleaseBuilder::new(inp.model_name, inp.model_version, inp.model_format);
    builder.primary_artifact(inp.primary_name.to_string(), primary_bytes);
    for spec in inp.framework {
        let (name, version) = parse_kv_pair(spec, "framework")?;
        builder.add_framework(FrameworkRef {
            name,
            version,
            cpe: None,
        });
    }
    for spec in inp.license {
        let (spdx_id, scope_str) = parse_kv_pair(spec, "license")?;
        let scope = parse_license_scope(&scope_str)?;
        builder.add_license(License {
            spdx_id,
            scope,
            text_uri: None,
        });
    }
    for spec in inp.safety_attestation {
        let (name, result) = parse_kv_pair(spec, "safety-attestation")?;
        builder.add_safety_attestation(SafetyAttestation {
            name,
            result,
            report_hash_algorithm: None,
            report_hash: None,
            report_uri: None,
        });
    }
    for spec in inp.export_control {
        let (regime, classification) = parse_kv_pair(spec, "export-control")?;
        builder.add_export_control(ExportControl {
            regime,
            classification,
            notes: None,
        });
    }
    builder.builder_id(inp.builder_id.to_string());
    builder.current_aion_version(inp.aion_version);

    // Transparency log for this seal; the log lives under the bundle
    // dir for auditors who want to replay the seal context.
    let mut log = TransparencyLog::new();
    let signed = builder
        .seal(AuthorId::new(inp.author), &signing_key, &mut log)
        .context("ReleaseBuilder::seal failed")?;

    let bundle = signed_release_to_bundle(&signed);
    let bundle_json = serde_json::to_string_pretty(&bundle).context("serialize bundle")?;

    std::fs::create_dir_all(inp.out_dir)
        .with_context(|| format!("create out-dir: {}", inp.out_dir.display()))?;
    let bundle_path = inp.out_dir.join("release.json");
    std::fs::write(&bundle_path, &bundle_json)
        .with_context(|| format!("write bundle: {}", bundle_path.display()))?;

    let primary_out = inp.out_dir.join("primary.bin");
    // Re-read the primary since seal consumed it. (ReleaseBuilder
    // owns the bytes; we need them on disk for verify to re-hash.)
    std::fs::copy(inp.primary, &primary_out).with_context(|| {
        format!(
            "copy primary to bundle: {} -> {}",
            inp.primary.display(),
            primary_out.display()
        )
    })?;

    println!(
        "\n✅ Sealed {} v{}",
        signed.model_ref.name, signed.model_ref.version
    );
    println!("   Bundle: {}", bundle_path.display());
    println!("   Primary: {}", primary_out.display());
    println!("   Log entries: {}", signed.log_entries.len());
    Ok(())
}

fn parse_kv_pair(spec: &str, label: &str) -> Result<(String, String)> {
    let (left, right) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("--{label} expects `<key>:<value>`, got: {spec}"))?;
    Ok((left.to_string(), right.to_string()))
}

fn parse_license_scope(s: &str) -> Result<aion_context::aibom::LicenseScope> {
    use aion_context::aibom::LicenseScope;
    match s.to_ascii_lowercase().as_str() {
        "weights" => Ok(LicenseScope::Weights),
        "source" | "source_code" | "sourcecode" => Ok(LicenseScope::SourceCode),
        "data" | "training_data" => Ok(LicenseScope::TrainingData),
        "docs" | "documentation" => Ok(LicenseScope::Documentation),
        "combined" => Ok(LicenseScope::Combined),
        other => Err(anyhow::anyhow!(
            "unknown license scope: {other} (expected weights|source|data|docs|combined)"
        )),
    }
}

fn signed_release_to_bundle(s: &aion_context::release::SignedRelease) -> ReleaseBundle {
    ReleaseBundle {
        signer: s.signer.as_u64(),
        model_ref: s.model_ref.clone(),
        manifest_canonical_hex: hex::encode(s.manifest.canonical_bytes()),
        manifest_signature: BundleSig {
            author_id: s.manifest_signature.author_id,
            public_key_hex: hex::encode(s.manifest_signature.public_key),
            signature_hex: hex::encode(s.manifest_signature.signature),
        },
        manifest_dsse: s.manifest_dsse.clone(),
        aibom: s.aibom.clone(),
        aibom_dsse: s.aibom_dsse.clone(),
        slsa_statement: s.slsa_statement.clone(),
        slsa_dsse: s.slsa_dsse.clone(),
        oci_primary: s.oci_primary.clone(),
        oci_aibom_referrer: s.oci_aibom_referrer.clone(),
        oci_slsa_referrer: s.oci_slsa_referrer.clone(),
        log_entries: s
            .log_entries
            .iter()
            .map(|l| BundleLogSeq {
                kind: l.kind as u16,
                seq: l.seq,
            })
            .collect(),
    }
}

fn bundle_to_signed_release(b: ReleaseBundle) -> Result<aion_context::release::SignedRelease> {
    use aion_context::manifest::ArtifactManifest;
    use aion_context::serializer::SignatureEntry;
    use aion_context::transparency_log::LogEntryKind;
    use aion_context::types::AuthorId;

    let manifest_bytes =
        hex::decode(&b.manifest_canonical_hex).context("decode manifest canonical hex")?;
    let manifest = ArtifactManifest::from_canonical_bytes(&manifest_bytes)
        .context("parse manifest from canonical bytes")?;

    let pk_bytes = hex::decode(&b.manifest_signature.public_key_hex)
        .context("decode manifest_signature.public_key_hex")?;
    let sig_bytes = hex::decode(&b.manifest_signature.signature_hex)
        .context("decode manifest_signature.signature_hex")?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("manifest_signature.public_key must be 32 bytes"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("manifest_signature.signature must be 64 bytes"))?;
    let manifest_signature = SignatureEntry::new(
        AuthorId::new(b.manifest_signature.author_id),
        pk_arr,
        sig_arr,
    );

    let mut log_entries: Vec<(LogEntryKind, u64)> = Vec::with_capacity(b.log_entries.len());
    for l in b.log_entries {
        let kind = LogEntryKind::from_u16(l.kind)
            .with_context(|| format!("unknown LogEntryKind: {}", l.kind))?;
        log_entries.push((kind, l.seq));
    }

    Ok(aion_context::release::SignedRelease::from_components(
        AuthorId::new(b.signer),
        b.model_ref,
        manifest,
        manifest_signature,
        b.manifest_dsse,
        b.aibom,
        b.aibom_dsse,
        b.slsa_statement,
        b.slsa_dsse,
        b.oci_primary,
        b.oci_aibom_referrer,
        b.oci_slsa_referrer,
        log_entries,
    ))
}

fn cmd_release_verify(
    bundle_dir: &std::path::Path,
    registry_path: &std::path::Path,
    at_version: u64,
) -> Result<ExitCode> {
    let bundle_path = bundle_dir.join("release.json");
    let bundle_json = std::fs::read_to_string(&bundle_path)
        .with_context(|| format!("read bundle: {}", bundle_path.display()))?;
    let bundle: ReleaseBundle = serde_json::from_str(&bundle_json).context("parse release.json")?;
    let signed = bundle_to_signed_release(bundle)?;
    let registry = load_registry_from_path(registry_path)?;

    println!(
        "🔍 Verifying release {} v{}",
        signed.model_ref.name, signed.model_ref.version
    );
    match signed.verify(&registry, at_version) {
        Ok(()) => {
            println!("✅ VALID at version {at_version}");
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("❌ INVALID: {e}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_release_inspect(bundle_dir: &std::path::Path, format: OutputFormat) -> Result<()> {
    let bundle_path = bundle_dir.join("release.json");
    let bundle_json = std::fs::read_to_string(&bundle_path)
        .with_context(|| format!("read bundle: {}", bundle_path.display()))?;
    let bundle: ReleaseBundle = serde_json::from_str(&bundle_json).context("parse release.json")?;

    match format {
        OutputFormat::Json => println!("{bundle_json}"),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(&bundle)?),
        OutputFormat::Text => {
            println!("Release bundle: {}", bundle_path.display());
            println!("  signer:        {}", bundle.signer);
            println!(
                "  model:         {} v{} ({})",
                bundle.model_ref.name, bundle.model_ref.version, bundle.model_ref.format
            );
            println!("  model size:    {} bytes", bundle.model_ref.size);
            println!(
                "  model hash:    {}  ({})",
                hex::encode(bundle.model_ref.hash),
                bundle.model_ref.hash_algorithm
            );
            println!("  frameworks:    {}", bundle.aibom.frameworks.len());
            println!("  licenses:      {}", bundle.aibom.licenses.len());
            println!(
                "  safety atts:   {}",
                bundle.aibom.safety_attestations.len()
            );
            println!("  export ctrl:   {}", bundle.aibom.export_controls.len());
            println!("  log entries:   {}", bundle.log_entries.len());
        }
    }
    Ok(())
}
