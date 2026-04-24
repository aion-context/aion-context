# RFC 0016: Command-Line Interface Design

- **Author:** UX Engineer (10+ years CLI design, developer tools expert)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

Complete specification for the AION v2 command-line interface (CLI). Defines all commands, arguments, output formats, and user experience patterns following modern CLI best practices. Emphasizes usability, discoverability, and consistent interaction patterns while supporting both basic and advanced use cases.

## Motivation

### Problem Statement

AION v2 requires a command-line interface that:

1. **Intuitive for New Users:** Clear command structure, helpful error messages
2. **Powerful for Experts:** Advanced options, scripting support, JSON output
3. **Consistent Experience:** Predictable patterns across all commands
4. **Cross-Platform:** Identical behavior on Windows, macOS, Linux
5. **Secure by Default:** Safe operations, confirmation for destructive actions

### Design Philosophy

**"Simple things simple, complex things possible"**

- **Progressive Disclosure:** Basic commands work with minimal arguments
- **Helpful Defaults:** Reasonable behavior without configuration
- **Clear Feedback:** Status updates, progress bars, meaningful errors
- **Scriptable:** JSON output, exit codes, minimal dependencies
- **Self-Documenting:** Built-in help, examples, auto-completion

## Proposal

### Command Structure

#### Top-Level Commands

```bash
aion <command> [options] [arguments]

Commands:
  init        Initialize new AION file
  commit      Create new version with changes
  show        Display file contents or history
  verify      Validate file integrity and signatures
  key         Manage cryptographic keys
  sync        Synchronize with cloud storage (optional)
  export      Export data in various formats
  import      Import data from external sources
  config      Manage configuration settings
  help        Show help information
```

#### Command Categories

**File Operations:**
- `init`, `commit`, `show`, `verify`

**Key Management:**
- `key generate`, `key list`, `key export`, `key import`

**Synchronization:**
- `sync init`, `sync push`, `sync pull`, `sync status`

**Data Exchange:**
- `export json`, `export yaml`, `import rules`

**Configuration:**
- `config get`, `config set`, `config list`

### Detailed Command Specifications

#### `aion init` - Initialize New File

Create a new AION file with initial rules and author configuration.

```bash
Usage: aion init [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to new AION file

Options:
  -a, --author-id <ID>      Author identifier (default: from config)
  -r, --rules <FILE>        Initial rules file (JSON/YAML)
  -f, --force               Overwrite existing file
      --no-encryption       Skip rules encryption (not recommended)
      --key-derivation <N>   Key derivation rounds (default: 100000)
  -h, --help                Show help
  -q, --quiet               Suppress output
  -v, --verbose             Verbose output

Examples:
  aion init myapp.aion
  aion init --author-id 1001 --rules config.json myapp.aion
  aion init --force existing.aion
```

**Output:**
```
✓ Generated new file ID: 0x1a2b3c4d5e6f7890
✓ Created author key for ID 1001
✓ Imported rules from config.json (1,234 bytes)
✓ Created genesis version (v1)
✓ File initialized: myapp.aion

Next steps:
  • View file: aion show myapp.aion
  • Make changes: edit your rules, then run 'aion commit'
  • Set up sync: aion sync init myapp.aion
```

#### `aion commit` - Create New Version

Commit changes to rules as a new version.

```bash
Usage: aion commit [OPTIONS] <FILE>

Arguments:
  <FILE>  AION file to commit to

Options:
  -a, --author-id <ID>      Author ID (default: from config)
  -r, --rules <FILE>        Updated rules file
  -m, --message <TEXT>      Commit message
      --stdin               Read rules from stdin
      --diff                Show diff before committing
      --dry-run             Show what would be committed
  -f, --force               Skip validation warnings
  -h, --help                Show help

Examples:
  aion commit -r updated_rules.json myapp.aion
  aion commit -m "Add new validation rules" myapp.aion
  cat rules.json | aion commit --stdin myapp.aion
  aion commit --diff --dry-run myapp.aion
```

**Output:**
```
➤ Analyzing changes...
  • Added 3 new rules
  • Modified 1 existing rule  
  • Deleted 0 rules

➤ Creating version 15...
✓ Rules encrypted and stored
✓ Version signed with author key 1001
✓ Audit trail updated

Version 15 committed successfully
  Author: 1001
  Timestamp: 2024-11-23T10:30:45Z
  Message: Add new validation rules
  Size: 2,456 bytes (+134 from v14)
```

#### `aion show` - Display Information

Show file contents, version history, or specific information.

```bash
Usage: aion show [OPTIONS] <FILE> [SUBCOMMAND]

Arguments:
  <FILE>  AION file to inspect

Subcommands:
  rules       Show current rules (default)
  history     Show version history  
  version     Show specific version
  signatures  Show signature information
  audit       Show audit trail
  info        Show file metadata

Options:
  -v, --version <N>         Show specific version
  -f, --format <FORMAT>     Output format (json|yaml|toml|table)
      --no-decrypt          Don't decrypt rules (show encrypted)
      --raw                 Raw binary output
  -n, --lines <N>          Limit output lines
      --author <ID>         Filter by author
      --since <DATE>        Show versions since date
      --until <DATE>        Show versions until date
  -h, --help               Show help

Examples:
  aion show myapp.aion                    # Current rules
  aion show --format json myapp.aion      # JSON output
  aion show myapp.aion history            # Version history
  aion show --version 10 myapp.aion       # Specific version
  aion show --author 1001 myapp.aion audit
```

**Output Examples:**

Current rules (default):
```yaml
# AION File: myapp.aion
# Current Version: 15 (2024-11-23T10:30:45Z)
# Author: 1001

validation:
  required_fields:
    - name
    - email
    - created_at
  max_length: 1000
  
permissions:
  read: [admin, user]
  write: [admin]
  delete: [admin]
```

Version history:
```
Version  Author  Date                 Message                    Size
v15      1001    2024-11-23 10:30:45  Add new validation rules   2,456 B
v14      1002    2024-11-23 09:15:22  Update permissions         2,322 B  
v13      1001    2024-11-22 16:45:33  Initial configuration      2,100 B
...      ...     ...                  ...                        ...
v1       1001    2024-11-20 08:00:00  Genesis version            1,850 B

Total: 15 versions, 3 authors, 14,234 bytes
```

#### `aion verify` - Validate Integrity

Verify cryptographic integrity and signatures.

```bash
Usage: aion verify [OPTIONS] <FILE>

Arguments:
  <FILE>  AION file to verify

Options:
      --signatures-only     Verify only signatures, skip structure
      --structure-only      Verify only file structure, skip signatures
      --version <N>         Verify specific version
      --author <ID>         Verify signatures from specific author
      --fix                 Attempt to fix minor issues
      --report <FILE>       Write detailed report to file
  -v, --verbose            Detailed verification output
  -q, --quiet              Only show errors
  -h, --help               Show help

Examples:
  aion verify myapp.aion
  aion verify --verbose --report audit.txt myapp.aion
  aion verify --signatures-only --author 1001 myapp.aion
```

**Output:**
```
➤ Verifying AION file: myapp.aion

File Structure:
✓ Magic number valid
✓ Version supported (v2)
✓ File size consistent (14,234 bytes)
✓ Section boundaries valid
✓ Header integrity valid

Version Chain:
✓ Genesis version present  
✓ Hash chain integrity (15 versions)
✓ Version sequence valid (1→15)
✓ Temporal ordering valid

Signatures:
✓ All versions signed (15/15)
✓ Valid Ed25519 signatures (15/15)
✓ Known authors: 1001, 1002, 1003
✓ No signature verification failures

Audit Trail:
✓ Complete audit trail (45 entries)
✓ Chronological ordering
✓ No missing events

Result: ✓ VALID
  Verified in 12ms
  15 versions, 3 authors, all signatures valid
```

#### `aion key` - Key Management

Manage cryptographic keys for signing.

```bash
Usage: aion key <SUBCOMMAND>

Subcommands:
  generate    Generate new author keypair
  list        List stored keys
  export      Export key for backup
  import      Import key from backup
  delete      Remove key from storage
  show        Show public key information

Global Options:
  -h, --help     Show help
  -q, --quiet    Suppress output
  -v, --verbose  Verbose output
```

**`aion key generate`:**
```bash
Usage: aion key generate [OPTIONS] <AUTHOR_ID>

Arguments:
  <AUTHOR_ID>  Numeric author identifier

Options:
      --algorithm <ALG>     Key algorithm (ed25519|rsa2048) [default: ed25519]  
      --no-store           Don't store in system keyring
      --export <FILE>      Export to file after generation
      --password           Prompt for export password
  -f, --force              Overwrite existing key
  -h, --help               Show help

Examples:
  aion key generate 1001
  aion key generate --export backup.key 1001
  aion key generate --no-store --export private.key 1001
```

**`aion key list`:**
```bash
Usage: aion key list [OPTIONS]

Options:
      --format <FORMAT>    Output format (table|json|csv)
      --show-public        Include public key in output
  -h, --help               Show help

Example:
  aion key list
```

Output:
```
Author ID  Algorithm  Created              Last Used           Storage
1001       Ed25519    2024-11-20 08:00:00  2024-11-23 10:30:45  System Keyring
1002       Ed25519    2024-11-21 14:30:22  2024-11-23 09:15:22  System Keyring  
1003       Ed25519    2024-11-22 11:45:10  Never               System Keyring

Total: 3 keys
```

#### `aion sync` - Cloud Synchronization

Synchronize files with cloud storage (optional feature).

```bash
Usage: aion sync <SUBCOMMAND>

Subcommands:
  init        Initialize sync for file
  push        Upload local changes
  pull        Download remote changes  
  status      Show sync status
  config      Configure sync settings
  devices     Manage synced devices

Examples:
  aion sync init --provider s3 myapp.aion
  aion sync push myapp.aion
  aion sync pull myapp.aion
  aion sync status myapp.aion
```

#### `aion export` - Export Data

Export file data in various formats.

```bash  
Usage: aion export [OPTIONS] <FILE> <FORMAT>

Arguments:
  <FILE>    AION file to export
  <FORMAT>  Export format (json|yaml|toml|csv|html|pdf)

Options:
  -o, --output <FILE>      Output file (default: stdout)
  -v, --version <N>        Export specific version
      --include-metadata   Include version metadata
      --include-history    Include complete history
      --template <FILE>    Use custom template
      --pretty             Pretty-print output
  -h, --help               Show help

Examples:
  aion export myapp.aion json
  aion export -o backup.yaml --include-history myapp.aion yaml
  aion export --version 10 myapp.aion json
```

#### `aion config` - Configuration

Manage global and per-file configuration.

```bash
Usage: aion config <SUBCOMMAND>

Subcommands:
  get         Get configuration value
  set         Set configuration value
  list        List all configuration
  init        Initialize configuration file
  edit        Edit configuration in $EDITOR

Global Options:
      --global    Modify global config (~/.aion/config.toml)
      --local     Modify local config (./aion.toml)
  -h, --help      Show help

Examples:
  aion config set default_author_id 1001
  aion config get sync.provider
  aion config list
  aion config --global set editor vim
```

### Global Options

All commands support these global options:

```bash
Global Options:
  -h, --help         Show help information
  -V, --version      Show version information
  -v, --verbose      Enable verbose output
  -q, --quiet        Suppress output except errors
      --color <WHEN> When to use colors (auto|always|never)
      --config <FILE> Use specific config file
      --no-progress   Disable progress bars
```

### Exit Codes

Consistent exit codes across all commands:

```bash
0   Success
1   General error
2   Invalid arguments or usage
3   File not found or permission denied
4   Cryptographic error (bad signature, corruption)
5   Network error (sync operations)
6   Configuration error
7   User cancelled operation
64  Command line usage error (BSD convention)
```

### Output Formats

#### Standard Output

**Success Operations:**
- ✓ Green checkmark for successful operations
- ➤ Arrow for in-progress operations  
- ⚠ Yellow warning symbol for warnings
- ✗ Red X for errors

**Progress Indicators:**
```bash
➤ Verifying signatures... ████████████████████████████████ 15/15 (100%) 
✓ All signatures valid (completed in 234ms)
```

**Tables:**
```
Version  Author  Date                 Message                    Size
v15      1001    2024-11-23 10:30:45  Add new validation rules   2,456 B
v14      1002    2024-11-23 09:15:22  Update permissions         2,322 B
```

#### JSON Output

All commands support `--format json` for scripting:

```json
{
  "command": "show",
  "file": "myapp.aion", 
  "result": {
    "current_version": 15,
    "author_id": 1001,
    "timestamp": "2024-11-23T10:30:45Z",
    "rules": {
      "validation": {
        "required_fields": ["name", "email", "created_at"]
      }
    }
  },
  "metadata": {
    "file_size": 14234,
    "versions_count": 15,
    "authors_count": 3
  }
}
```

### Error Handling

#### Error Message Format

```bash
Error: <brief description>
  
  <detailed explanation>
  
  Suggestion: <what user can do to fix>
  
  For more help: aion help <command>
```

#### Example Error Messages

**File Not Found:**
```bash
Error: File not found: myapp.aion

  The specified AION file does not exist or cannot be accessed.
  
  Suggestion: Check the file path and permissions, or create a new file with:
    aion init myapp.aion
    
  For more help: aion help init
```

**Signature Verification Failed:**
```bash  
Error: Signature verification failed for version 12

  The signature for version 12 (author 1002) is invalid. This could indicate
  file corruption or tampering.
  
  Details:
    • Version: 12
    • Author: 1002  
    • Expected signature: a1b2c3d4...
    • Actual signature: e5f6g7h8...
  
  Suggestion: Verify the file integrity with 'aion verify' or restore from backup.
  
  For more help: aion help verify
```

### Configuration Files

#### Global Configuration (`~/.aion/config.toml`)

```toml
[general]
default_author_id = 1001
editor = "vim"
pager = "less"
color = "auto"

[crypto]  
key_derivation_rounds = 100000
signature_algorithm = "ed25519"

[sync]
provider = "s3"
auto_sync = false
background_interval = 300

[output]
default_format = "yaml" 
show_progress = true
verbose = false

[providers.s3]
bucket = "my-aion-files"
region = "us-west-2"
```

#### Per-File Configuration (`aion.toml`)

```toml
[file]
author_id = 1001
auto_commit = false

[sync]
enabled = true
provider = "gdrive"

[export]  
default_format = "json"
include_metadata = true
```

### Auto-Completion

Support shell auto-completion for commands, options, and file paths:

```bash
# Bash completion
$ aion <TAB>
commit  config  export  help  init  key  show  sync  verify

$ aion show myapp.aion <TAB>
audit  history  info  rules  signatures  version

$ aion key <TAB>  
delete  export  generate  import  list  show
```

### Help System

#### Built-in Help

```bash
$ aion help
AION v2.0.0 - Cryptographically Secured Configuration Management

USAGE:
    aion <COMMAND> [OPTIONS] [ARGS]

COMMANDS:
    init      Initialize new AION file
    commit    Create new version with changes
    show      Display file contents or history
    verify    Validate file integrity and signatures
    key       Manage cryptographic keys
    sync      Synchronize with cloud storage
    export    Export data in various formats
    config    Manage configuration settings
    help      Show help information

OPTIONS:
    -h, --help       Show help information
    -V, --version    Show version information  
    -v, --verbose    Enable verbose output
    -q, --quiet      Suppress output except errors

EXAMPLES:
    aion init myapp.aion                    Create new AION file
    aion commit -r rules.json myapp.aion    Update rules
    aion show myapp.aion history            Show version history
    aion verify myapp.aion                  Validate integrity

For detailed help on a specific command, run:
    aion help <command>

Documentation: https://aion-context.dev/docs
```

#### Command-Specific Help

```bash
$ aion help init
aion-init - Initialize new AION file

USAGE:
    aion init [OPTIONS] <FILE>

ARGUMENTS:  
    <FILE>  Path to new AION file

OPTIONS:
    -a, --author-id <ID>      Author identifier (default: from config)
    -r, --rules <FILE>        Initial rules file (JSON/YAML)  
    -f, --force               Overwrite existing file
        --no-encryption       Skip rules encryption (not recommended)
    -h, --help                Show help
    -q, --quiet               Suppress output
    -v, --verbose             Verbose output

EXAMPLES:
    # Create new file with default settings
    aion init myapp.aion
    
    # Create with specific author and initial rules
    aion init --author-id 1001 --rules config.json myapp.aion
    
    # Force overwrite existing file
    aion init --force existing.aion

NOTES:
    • Author keys are stored in the system keyring
    • Initial rules can be JSON, YAML, or TOML format
    • File encryption is enabled by default for security
```

## Implementation Details

### Command Line Parser

Use `clap` (Rust) for argument parsing with derive macros:

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aion")]
#[command(about = "Cryptographically Secured Configuration Management")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
    
    /// Suppress output except errors
    #[arg(short, long, global = true)]  
    quiet: bool,
    
    /// Configuration file path
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize new AION file
    Init(InitArgs),
    /// Create new version with changes
    Commit(CommitArgs),
    /// Display file contents or history
    Show(ShowArgs),
    // ... other commands
}
```

### Progress Reporting

```rust
use indicatif::{ProgressBar, ProgressStyle};

fn show_progress(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("➤ {msg} {bar:32} {pos}/{len} ({percent}%)")
            .progress_chars("████▓▒░")
    );
    pb.set_message(message.to_string());
    pb
}
```

### Error Handling

```rust
use anyhow::{Context, Result};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("File not found: {path}")]
    FileNotFound { path: PathBuf },
    
    #[error("Invalid author ID: {id}")]
    InvalidAuthorId { id: String },
    
    #[error("Signature verification failed for version {version}")]
    SignatureVerificationFailed { version: u64 },
}

// Usage in commands
fn init_command(args: InitArgs) -> Result<()> {
    let file_path = &args.file;
    
    if file_path.exists() && !args.force {
        return Err(CliError::FileAlreadyExists { 
            path: file_path.clone() 
        }.into());
    }
    
    // ... implementation
    
    Ok(())
}
```

## Testing Strategy

### Unit Tests

Test individual command parsing and validation:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    
    #[test]
    fn test_init_command_parsing() {
        let cli = Cli::try_parse_from(&[
            "aion", "init", "--author-id", "1001", "test.aion"
        ]).unwrap();
        
        match cli.command {
            Commands::Init(args) => {
                assert_eq!(args.author_id, Some(1001));
                assert_eq!(args.file, PathBuf::from("test.aion"));
            }
            _ => panic!("Expected Init command"),
        }
    }
    
    #[test]
    fn test_help_generation() {
        // Ensure help can be generated for all commands
        let mut cmd = Cli::command();
        cmd.debug_assert();
    }
}
```

### Integration Tests

Test complete command workflows:

```bash
#!/bin/bash
# Test complete workflow

# Initialize file
./target/debug/aion init --author-id 1001 test.aion
test $? -eq 0 || exit 1

# Show initial state  
./target/debug/aion show test.aion
test $? -eq 0 || exit 1

# Commit changes
echo '{"test": "data"}' > rules.json
./target/debug/aion commit -r rules.json test.aion
test $? -eq 0 || exit 1

# Verify integrity
./target/debug/aion verify test.aion
test $? -eq 0 || exit 1

echo "All tests passed!"
```

### User Experience Testing

- Shell completion functionality
- Error message clarity
- Help system completeness
- Cross-platform compatibility
- Performance with large files

## Implementation Plan

### Phase 1: Core Commands (Week 1-2)
- Implement `init`, `commit`, `show`, `verify`
- Basic error handling and help
- Configuration file support

### Phase 2: Key Management (Week 3)
- Implement `key` subcommands
- Keyring integration
- Key export/import functionality

### Phase 3: Advanced Features (Week 4)
- Export/import commands
- Sync commands (if sync implemented)
- Advanced output formatting

### Phase 4: Polish (Week 5)
- Shell completion
- Man pages
- Performance optimization
- Cross-platform testing

## References

- [Command Line Interface Guidelines](https://clig.dev/)
- [clap Documentation](https://docs.rs/clap/)
- [Git CLI Design Patterns](https://git-scm.com/docs)
- [The Art of Command Line](https://github.com/jlevy/the-art-of-command-line)
- [CLI Style Guide](https://devcenter.heroku.com/articles/cli-style-guide)

## Appendix

### Complete Command Reference

```bash
aion init [OPTIONS] <FILE>
aion commit [OPTIONS] <FILE>
aion show [OPTIONS] <FILE> [SUBCOMMAND]
aion verify [OPTIONS] <FILE>
aion key generate [OPTIONS] <AUTHOR_ID>
aion key list [OPTIONS]
aion key export [OPTIONS] <AUTHOR_ID> <FILE>
aion key import [OPTIONS] <FILE>
aion key delete [OPTIONS] <AUTHOR_ID>
aion key show [OPTIONS] <AUTHOR_ID>
aion sync init [OPTIONS] <FILE>
aion sync push [OPTIONS] <FILE>  
aion sync pull [OPTIONS] <FILE>
aion sync status [OPTIONS] <FILE>
aion export [OPTIONS] <FILE> <FORMAT>
aion import [OPTIONS] <FILE>
aion config get [OPTIONS] <KEY>
aion config set [OPTIONS] <KEY> <VALUE>
aion config list [OPTIONS]
aion help [COMMAND]
```

### Environment Variables

```bash
AION_CONFIG_DIR     # Configuration directory (default: ~/.aion)
AION_AUTHOR_ID      # Default author ID
AION_EDITOR         # Editor for interactive operations
AION_PAGER          # Pager for long output
AION_NO_COLOR       # Disable colored output
AION_LOG_LEVEL      # Log level (error|warn|info|debug)
```

### Shell Integration

```bash
# Add to ~/.bashrc or ~/.zshrc
eval "$(aion completion bash)"  # or zsh, fish

# Enable git-style aliases
alias aion-init='aion init'
alias aion-commit='aion commit' 
alias aion-show='aion show'
```
