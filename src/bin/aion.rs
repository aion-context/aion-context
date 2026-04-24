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
    let mut registry = if output.exists() {
        let existing = std::fs::read_to_string(output)
            .with_context(|| format!("Failed to read existing registry: {}", output.display()))?;
        aion_context::key_registry::KeyRegistry::from_trusted_json(&existing)
            .with_context(|| format!("Failed to parse existing registry: {}", output.display()))?
    } else {
        aion_context::key_registry::KeyRegistry::new()
    };
    registry
        .register_author(
            author_id,
            master_signer.verifying_key(),
            op_signer.verifying_key(),
            0,
        )
        .with_context(|| format!("Failed to pin author {author}"))?;

    let json = registry
        .to_trusted_json()
        .context("Failed to serialize registry")?;
    std::fs::write(output, json)
        .with_context(|| format!("Failed to write registry file: {}", output.display()))?;

    println!("✅ Pinned author {author} with key '{key_id}'");
    println!("   Registry: {}", output.display());
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
