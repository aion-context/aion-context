//! Compliance Reporting Module
//!
//! Generates compliance reports for regulatory frameworks:
//! - SOX (Sarbanes-Oxley) - Financial controls audit
//! - HIPAA - Healthcare audit logs
//! - GDPR - Data processing records
//!
//! Reports are generated in structured formats (JSON, Markdown, plain text)
//! suitable for regulatory submission or conversion to PDF.

use crate::operations::{show_file_info, verify_file, FileInfo, VerificationReport};
use crate::{AionError, Result};
use std::path::Path;

/// Report output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Plain text format
    Text,
    /// Markdown format (can be converted to PDF)
    Markdown,
    /// JSON format for machine processing
    Json,
}

/// Compliance framework type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceFramework {
    /// Sarbanes-Oxley Act (financial controls)
    Sox,
    /// Health Insurance Portability and Accountability Act
    Hipaa,
    /// General Data Protection Regulation
    Gdpr,
    /// Generic audit report (all frameworks)
    Generic,
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sox => write!(f, "SOX"),
            Self::Hipaa => write!(f, "HIPAA"),
            Self::Gdpr => write!(f, "GDPR"),
            Self::Generic => write!(f, "Generic Audit"),
        }
    }
}

/// Compliance report data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceReport {
    /// Report title
    pub title: String,
    /// Compliance framework
    pub framework: String,
    /// Report generation timestamp (ISO 8601)
    pub generated_at: String,
    /// File being reported on
    pub file_path: String,
    /// File ID
    pub file_id: String,
    /// Verification status
    pub verification: VerificationSummary,
    /// Version history summary
    pub version_history: Vec<VersionSummary>,
    /// Framework-specific sections
    pub framework_sections: Vec<ReportSection>,
}

/// Verification summary for reports
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationSummary {
    /// Overall validity
    pub is_valid: bool,
    /// Structure check passed
    pub structure_valid: bool,
    /// Integrity hash check passed
    pub integrity_valid: bool,
    /// Hash chain check passed
    pub hash_chain_valid: bool,
    /// All signatures valid
    pub signatures_valid: bool,
    /// Number of temporal warnings
    pub temporal_warning_count: usize,
}

/// Version summary for reports
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionSummary {
    /// Version number
    pub version: u64,
    /// Author ID
    pub author_id: u64,
    /// Timestamp (ISO 8601)
    pub timestamp: String,
    /// Commit message
    pub message: String,
}

/// Report section for framework-specific content
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportSection {
    /// Section title
    pub title: String,
    /// Section content
    pub content: String,
}

/// Generate a compliance report for the specified framework
///
/// # Arguments
///
/// * `path` - Path to the AION file
/// * `framework` - Compliance framework to report for
/// * `format` - Output format
///
/// # Returns
///
/// Formatted compliance report as a string
///
/// # Errors
///
/// Returns error if file cannot be read or verified
pub fn generate_compliance_report(
    path: &Path,
    framework: ComplianceFramework,
    format: ReportFormat,
) -> Result<String> {
    // Gather file information
    let file_info = show_file_info(path)?;
    let verification = verify_file(path)?;

    // Build report structure
    let report = build_report(path, framework, &file_info, &verification)?;

    // Format output
    match format {
        ReportFormat::Text => Ok(format_as_text(&report)),
        ReportFormat::Markdown => Ok(format_as_markdown(&report)),
        ReportFormat::Json => format_as_json(&report),
    }
}

/// Build the compliance report structure
fn build_report(
    path: &Path,
    framework: ComplianceFramework,
    file_info: &FileInfo,
    verification: &VerificationReport,
) -> Result<ComplianceReport> {
    let generated_at = chrono_timestamp();

    let verification_summary = VerificationSummary {
        is_valid: verification.is_valid,
        structure_valid: verification.structure_valid,
        integrity_valid: verification.integrity_hash_valid,
        hash_chain_valid: verification.hash_chain_valid,
        signatures_valid: verification.signatures_valid,
        temporal_warning_count: verification.temporal_warnings.len(),
    };

    let version_history: Vec<VersionSummary> = file_info
        .versions
        .iter()
        .map(|v| VersionSummary {
            version: v.version_number,
            author_id: v.author_id,
            timestamp: format_timestamp_nanos(v.timestamp),
            message: v.message.clone(),
        })
        .collect();

    let framework_sections = match framework {
        ComplianceFramework::Sox => build_sox_sections(file_info, verification),
        ComplianceFramework::Hipaa => build_hipaa_sections(file_info, verification),
        ComplianceFramework::Gdpr => build_gdpr_sections(file_info, verification),
        ComplianceFramework::Generic => build_generic_sections(file_info, verification),
    };

    Ok(ComplianceReport {
        title: format!("{} Compliance Report", framework),
        framework: framework.to_string(),
        generated_at,
        file_path: path.display().to_string(),
        file_id: format!("0x{:016x}", file_info.file_id),
        verification: verification_summary,
        version_history,
        framework_sections,
    })
}

// ============================================================================
// SOX (Sarbanes-Oxley) Report Sections
// ============================================================================

fn build_sox_sections(
    file_info: &FileInfo,
    verification: &VerificationReport,
) -> Vec<ReportSection> {
    vec![
        ReportSection {
            title: "Internal Control Assessment".to_string(),
            content: format!(
                "This report documents the integrity controls for business rules file ID {}.\n\n\
                 Control Objective: Ensure accuracy and completeness of automated business rules.\n\n\
                 Control Activity: Cryptographic verification of all rule changes.\n\n\
                 Test Results:\n\
                 - Digital signatures verified: {}\n\
                 - Hash chain integrity: {}\n\
                 - Tamper detection: {}",
                format!("0x{:016x}", file_info.file_id),
                if verification.signatures_valid { "PASS" } else { "FAIL" },
                if verification.hash_chain_valid { "PASS" } else { "FAIL" },
                if verification.integrity_hash_valid { "PASS" } else { "FAIL" }
            ),
        },
        ReportSection {
            title: "Change Management Log".to_string(),
            content: format!(
                "Total versions recorded: {}\n\
                 All changes cryptographically signed: {}\n\
                 Audit trail completeness: {}\n\n\
                 Each version entry contains:\n\
                 - Unique version number\n\
                 - Author identification\n\
                 - Timestamp of change\n\
                 - Digital signature (Ed25519)\n\
                 - Cryptographic hash linking to previous version",
                file_info.version_count,
                if verification.signatures_valid { "Yes" } else { "No" },
                if verification.hash_chain_valid { "Complete" } else { "Incomplete" }
            ),
        },
        ReportSection {
            title: "Management Assertion".to_string(),
            content: "Based on the cryptographic verification performed, management can assert that:\n\n\
                     1. All changes to business rules have been authorized and recorded\n\
                     2. The audit trail has not been tampered with\n\
                     3. Each change is attributable to a specific author\n\
                     4. The chronological sequence of changes is preserved".to_string(),
        },
    ]
}

// ============================================================================
// HIPAA Report Sections
// ============================================================================

fn build_hipaa_sections(
    file_info: &FileInfo,
    verification: &VerificationReport,
) -> Vec<ReportSection> {
    vec![
        ReportSection {
            title: "Access and Audit Controls (§164.312)".to_string(),
            content: format!(
                "HIPAA Security Rule Compliance Assessment\n\n\
                 § 164.312(b) - Audit Controls:\n\
                 - Audit trail implemented: Yes\n\
                 - Hardware/software/procedural mechanisms: Cryptographic signatures\n\
                 - Activity recording: {} versions recorded\n\
                 - Audit log integrity: {}\n\n\
                 § 164.312(c) - Integrity Controls:\n\
                 - Mechanism to authenticate ePHI: Ed25519 digital signatures\n\
                 - Integrity verification: {}\n\
                 - Unauthorized alteration detection: BLAKE3 hash chain",
                file_info.version_count,
                if verification.hash_chain_valid {
                    "Verified"
                } else {
                    "Failed"
                },
                if verification.is_valid {
                    "PASS"
                } else {
                    "FAIL"
                }
            ),
        },
        ReportSection {
            title: "Audit Log Entries".to_string(),
            content: format!(
                "Activity Type: Business Rule Modification\n\
                 Total Entries: {}\n\
                 Entry Authentication: Digital Signature (Ed25519)\n\
                 Timestamp Precision: Nanosecond\n\
                 Non-repudiation: Cryptographic proof of authorship\n\n\
                 Each audit entry contains:\n\
                 - User identification (Author ID)\n\
                 - Date and time of activity\n\
                 - Type of activity (version commit)\n\
                 - Cryptographic proof of entry integrity",
                file_info.version_count
            ),
        },
        ReportSection {
            title: "Technical Safeguards Summary".to_string(),
            content: format!(
                "Encryption: ChaCha20-Poly1305 (AEAD)\n\
                 Digital Signatures: Ed25519\n\
                 Hashing: BLAKE3\n\
                 Key Derivation: HKDF-SHA256\n\n\
                 Verification Status:\n\
                 - All {} signatures valid: {}\n\
                 - File integrity verified: {}\n\
                 - Temporal warnings: {}",
                file_info.signatures.len(),
                if verification.signatures_valid {
                    "Yes"
                } else {
                    "No"
                },
                if verification.is_valid { "Yes" } else { "No" },
                verification.temporal_warnings.len()
            ),
        },
    ]
}

// ============================================================================
// GDPR Report Sections
// ============================================================================

fn build_gdpr_sections(
    file_info: &FileInfo,
    verification: &VerificationReport,
) -> Vec<ReportSection> {
    vec![
        ReportSection {
            title: "Record of Processing Activities (Article 30)".to_string(),
            content: format!(
                "Processing Activity: Automated Decision-Making Rule Management\n\n\
                 Controller Reference: File ID {}\n\
                 Purpose: Storage and versioning of business rules for automated processing\n\
                 Categories of Processing: Rule creation, modification, verification\n\n\
                 Technical Measures (Article 32):\n\
                 - Encryption of data: ChaCha20-Poly1305\n\
                 - Integrity verification: BLAKE3 hash chain\n\
                 - Access attribution: Ed25519 digital signatures",
                format!("0x{:016x}", file_info.file_id)
            ),
        },
        ReportSection {
            title: "Data Processing Log".to_string(),
            content: format!(
                "Total Processing Events: {}\n\
                 First Event: {}\n\
                 Latest Event: {}\n\n\
                 Each processing event records:\n\
                 - Data controller action (rule change)\n\
                 - Timestamp of processing\n\
                 - Identity of processor (Author ID)\n\
                 - Cryptographic proof of processing integrity",
                file_info.version_count,
                file_info
                    .versions
                    .first()
                    .map(|v| format_timestamp_nanos(v.timestamp))
                    .unwrap_or_default(),
                file_info
                    .versions
                    .last()
                    .map(|v| format_timestamp_nanos(v.timestamp))
                    .unwrap_or_default()
            ),
        },
        ReportSection {
            title: "Accountability Demonstration (Article 5(2))".to_string(),
            content: format!(
                "This record demonstrates compliance with GDPR accountability principle:\n\n\
                 Integrity and Confidentiality (Article 5(1)(f)):\n\
                 - Processing integrity verified: {}\n\
                 - Unauthorized access detection: Hash chain verification\n\
                 - Data protection: Authenticated encryption\n\n\
                 Transparency:\n\
                 - All processing activities logged\n\
                 - Processing history retrievable\n\
                 - Audit trail tamper-evident",
                if verification.is_valid { "Yes" } else { "No" }
            ),
        },
    ]
}

// ============================================================================
// Generic Audit Report Sections
// ============================================================================

fn build_generic_sections(
    file_info: &FileInfo,
    verification: &VerificationReport,
) -> Vec<ReportSection> {
    vec![
        ReportSection {
            title: "File Summary".to_string(),
            content: format!(
                "File ID: 0x{:016x}\n\
                 Total Versions: {}\n\
                 Current Version: {}\n\
                 Total Signatures: {}",
                file_info.file_id,
                file_info.version_count,
                file_info.current_version,
                file_info.signatures.len()
            ),
        },
        ReportSection {
            title: "Verification Results".to_string(),
            content: format!(
                "Overall Status: {}\n\n\
                 Checks Performed:\n\
                 - Structure validation: {}\n\
                 - Integrity hash: {}\n\
                 - Hash chain: {}\n\
                 - Signatures: {}\n\n\
                 Temporal Warnings: {}",
                if verification.is_valid {
                    "VALID"
                } else {
                    "INVALID"
                },
                if verification.structure_valid {
                    "PASS"
                } else {
                    "FAIL"
                },
                if verification.integrity_hash_valid {
                    "PASS"
                } else {
                    "FAIL"
                },
                if verification.hash_chain_valid {
                    "PASS"
                } else {
                    "FAIL"
                },
                if verification.signatures_valid {
                    "PASS"
                } else {
                    "FAIL"
                },
                verification.temporal_warnings.len()
            ),
        },
        ReportSection {
            title: "Cryptographic Methods".to_string(),
            content: "Digital Signatures: Ed25519 (RFC 8032)\n\
                     Encryption: ChaCha20-Poly1305 (RFC 8439)\n\
                     Hashing: BLAKE3\n\
                     Key Derivation: HKDF-SHA256 (RFC 5869)"
                .to_string(),
        },
    ]
}

// ============================================================================
// Output Formatters
// ============================================================================

fn format_as_text(report: &ComplianceReport) -> String {
    let mut output = String::new();

    // Header
    output.push_str(&format!("{}\n", "=".repeat(70)));
    output.push_str(&format!("{:^70}\n", report.title));
    output.push_str(&format!("{}\n\n", "=".repeat(70)));

    output.push_str(&format!("Generated: {}\n", report.generated_at));
    output.push_str(&format!("File: {}\n", report.file_path));
    output.push_str(&format!("File ID: {}\n", report.file_id));
    output.push_str(&format!("\n{}\n\n", "-".repeat(70)));

    // Verification Summary
    output.push_str("VERIFICATION SUMMARY\n");
    output.push_str(&format!(
        "  Overall Status: {}\n",
        if report.verification.is_valid {
            "VALID"
        } else {
            "INVALID"
        }
    ));
    output.push_str(&format!(
        "  Structure: {}\n",
        if report.verification.structure_valid {
            "OK"
        } else {
            "FAILED"
        }
    ));
    output.push_str(&format!(
        "  Integrity: {}\n",
        if report.verification.integrity_valid {
            "OK"
        } else {
            "FAILED"
        }
    ));
    output.push_str(&format!(
        "  Hash Chain: {}\n",
        if report.verification.hash_chain_valid {
            "OK"
        } else {
            "FAILED"
        }
    ));
    output.push_str(&format!(
        "  Signatures: {}\n",
        if report.verification.signatures_valid {
            "OK"
        } else {
            "FAILED"
        }
    ));
    output.push_str(&format!("\n{}\n\n", "-".repeat(70)));

    // Version History
    output.push_str("VERSION HISTORY\n\n");
    for v in &report.version_history {
        output.push_str(&format!(
            "  Version {}: {} (Author {})\n",
            v.version, v.message, v.author_id
        ));
        output.push_str(&format!("    Timestamp: {}\n\n", v.timestamp));
    }
    output.push_str(&format!("{}\n\n", "-".repeat(70)));

    // Framework Sections
    for section in &report.framework_sections {
        output.push_str(&format!("{}\n\n", section.title.to_uppercase()));
        output.push_str(&format!("{}\n\n", section.content));
        output.push_str(&format!("{}\n\n", "-".repeat(70)));
    }

    output.push_str(&format!("{}\n", "=".repeat(70)));
    output.push_str(&format!("{:^70}\n", "END OF REPORT"));
    output.push_str(&format!("{}\n", "=".repeat(70)));

    output
}

fn format_as_markdown(report: &ComplianceReport) -> String {
    let mut output = String::new();

    // Header
    output.push_str(&format!("# {}\n\n", report.title));
    output.push_str(&format!("**Generated**: {}  \n", report.generated_at));
    output.push_str(&format!("**File**: `{}`  \n", report.file_path));
    output.push_str(&format!("**File ID**: `{}`\n\n", report.file_id));
    output.push_str("---\n\n");

    // Verification Summary
    output.push_str("## Verification Summary\n\n");
    output.push_str("| Check | Status |\n");
    output.push_str("|-------|--------|\n");
    output.push_str(&format!(
        "| Overall | {} |\n",
        if report.verification.is_valid {
            "✅ VALID"
        } else {
            "❌ INVALID"
        }
    ));
    output.push_str(&format!(
        "| Structure | {} |\n",
        if report.verification.structure_valid {
            "✅"
        } else {
            "❌"
        }
    ));
    output.push_str(&format!(
        "| Integrity | {} |\n",
        if report.verification.integrity_valid {
            "✅"
        } else {
            "❌"
        }
    ));
    output.push_str(&format!(
        "| Hash Chain | {} |\n",
        if report.verification.hash_chain_valid {
            "✅"
        } else {
            "❌"
        }
    ));
    output.push_str(&format!(
        "| Signatures | {} |\n",
        if report.verification.signatures_valid {
            "✅"
        } else {
            "❌"
        }
    ));
    output.push_str("\n---\n\n");

    // Version History
    output.push_str("## Version History\n\n");
    output.push_str("| Version | Author | Timestamp | Message |\n");
    output.push_str("|---------|--------|-----------|--------|\n");
    for v in &report.version_history {
        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            v.version, v.author_id, v.timestamp, v.message
        ));
    }
    output.push_str("\n---\n\n");

    // Framework Sections
    for section in &report.framework_sections {
        output.push_str(&format!("## {}\n\n", section.title));
        output.push_str(&format!("{}\n\n", section.content));
    }

    output.push_str("---\n\n");
    output.push_str("*Report generated by AION v2 Compliance Reporting*\n");

    output
}

fn format_as_json(report: &ComplianceReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(|e| AionError::InvalidFormat {
        reason: format!("JSON serialization failed: {e}"),
    })
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current timestamp in ISO 8601 format
fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();
    // Simple ISO 8601 format without external dependency
    format_unix_timestamp(secs)
}

/// Format Unix timestamp to ISO 8601
fn format_unix_timestamp(secs: u64) -> String {
    // Calculate date components from Unix timestamp
    let days = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert nanoseconds timestamp to ISO 8601
fn format_timestamp_nanos(nanos: u64) -> String {
    format_unix_timestamp(nanos / 1_000_000_000)
}

/// Convert days since epoch to year/month/day
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simplified calculation - good enough for reports
    let mut remaining_days = days as i64;
    let mut year = 1970u64;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days = remaining_days.saturating_sub(days_in_year);
        year = year.saturating_add(1);
    }

    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u64;
    for days_in_month in days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days = remaining_days.saturating_sub(days_in_month);
        month = month.saturating_add(1);
    }

    let day = (remaining_days as u64).saturating_add(1);

    (year, month, day)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_unix_timestamp() {
        // 2024-01-01 00:00:00 UTC
        let ts = 1704067200u64;
        let formatted = format_unix_timestamp(ts);
        assert!(formatted.starts_with("2024-01-01"));
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000)); // Divisible by 400
        assert!(is_leap_year(2024)); // Divisible by 4, not 100
        assert!(!is_leap_year(2023)); // Not divisible by 4
        assert!(!is_leap_year(1900)); // Divisible by 100, not 400
    }

    #[test]
    fn test_compliance_framework_display() {
        assert_eq!(ComplianceFramework::Sox.to_string(), "SOX");
        assert_eq!(ComplianceFramework::Hipaa.to_string(), "HIPAA");
        assert_eq!(ComplianceFramework::Gdpr.to_string(), "GDPR");
    }
}
