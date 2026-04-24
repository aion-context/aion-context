//! Export/Import Module
//!
//! Provides export and import functionality for AION files in various formats:
//! - JSON: Full file metadata export
//! - YAML: Human-readable configuration export  
//! - CSV: Audit trail export for spreadsheet analysis

use crate::operations::{show_file_info, FileInfo};
use crate::{AionError, Result};
use std::path::Path;

/// Export format options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// JSON format (full metadata)
    Json,
    /// YAML format (human-readable)
    Yaml,
    /// CSV format (audit trail only)
    Csv,
}

/// Exportable file data structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportData {
    /// Export format version
    pub export_version: String,
    /// Original file path
    pub source_file: String,
    /// File metadata
    pub file_info: ExportFileInfo,
    /// Version history
    pub versions: Vec<ExportVersion>,
    /// Signature information
    pub signatures: Vec<ExportSignature>,
}

/// Exported file information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportFileInfo {
    /// File ID (hex string)
    pub file_id: String,
    /// Total version count
    pub version_count: u64,
    /// Current (latest) version number
    pub current_version: u64,
}

/// Exported version entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportVersion {
    /// Version number
    pub version: u64,
    /// Author ID
    pub author_id: u64,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Commit message
    pub message: String,
    /// Rules content hash (hex)
    pub rules_hash: String,
    /// Parent version hash (hex, null for genesis)
    pub parent_hash: Option<String>,
}

/// Exported signature entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportSignature {
    /// Version number
    pub version: u64,
    /// Author ID
    pub author_id: u64,
    /// Public key (hex)
    pub public_key: String,
    /// Verification status
    pub verified: bool,
}

/// Export an AION file to the specified format
///
/// # Arguments
///
/// * `path` - Path to the AION file
/// * `format` - Export format (JSON, YAML, CSV)
///
/// # Returns
///
/// Exported data as a string in the requested format
pub fn export_file(path: &Path, format: ExportFormat) -> Result<String> {
    let file_info = show_file_info(path)?;

    match format {
        ExportFormat::Json => export_json(path, &file_info),
        ExportFormat::Yaml => export_yaml(path, &file_info),
        ExportFormat::Csv => export_csv(&file_info),
    }
}

/// Export to JSON format
fn export_json(path: &Path, file_info: &FileInfo) -> Result<String> {
    let export_data = build_export_data(path, file_info);
    serde_json::to_string_pretty(&export_data).map_err(|e| AionError::InvalidFormat {
        reason: format!("JSON serialization failed: {e}"),
    })
}

/// Export to YAML format
fn export_yaml(path: &Path, file_info: &FileInfo) -> Result<String> {
    let export_data = build_export_data(path, file_info);
    serde_yaml::to_string(&export_data).map_err(|e| AionError::InvalidFormat {
        reason: format!("YAML serialization failed: {e}"),
    })
}

/// Export audit trail to CSV format
fn export_csv(file_info: &FileInfo) -> Result<String> {
    let mut output = String::new();

    // Header row
    output.push_str("version,author_id,timestamp,message,rules_hash,parent_hash\n");

    // Data rows
    for version in &file_info.versions {
        let timestamp = format_timestamp_nanos(version.timestamp);
        let rules_hash = hex::encode(version.rules_hash);
        let parent_hash = version
            .parent_hash
            .map(|h| hex::encode(h))
            .unwrap_or_default();

        // Escape message for CSV (handle commas and quotes)
        let escaped_message = escape_csv_field(&version.message);

        output.push_str(&format!(
            "{},{},{},{},{},{}\n",
            version.version_number,
            version.author_id,
            timestamp,
            escaped_message,
            rules_hash,
            parent_hash
        ));
    }

    Ok(output)
}

/// Build export data structure from file info
fn build_export_data(path: &Path, file_info: &FileInfo) -> ExportData {
    ExportData {
        export_version: "1.0".to_string(),
        source_file: path.display().to_string(),
        file_info: ExportFileInfo {
            file_id: format!("0x{:016x}", file_info.file_id),
            version_count: file_info.version_count,
            current_version: file_info.current_version,
        },
        versions: file_info
            .versions
            .iter()
            .map(|v| ExportVersion {
                version: v.version_number,
                author_id: v.author_id,
                timestamp: format_timestamp_nanos(v.timestamp),
                message: v.message.clone(),
                rules_hash: hex::encode(v.rules_hash),
                parent_hash: v.parent_hash.map(|h| hex::encode(h)),
            })
            .collect(),
        signatures: file_info
            .signatures
            .iter()
            .map(|s| ExportSignature {
                version: s.version_number,
                author_id: s.author_id,
                public_key: hex::encode(s.public_key),
                verified: s.verified,
            })
            .collect(),
    }
}

/// Escape a field for CSV output
fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Format nanosecond timestamp to ISO 8601
fn format_timestamp_nanos(nanos: u64) -> String {
    let secs = nanos / 1_000_000_000;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since epoch to year/month/day
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut remaining_days = days as i64;
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
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
        remaining_days -= days_in_month;
        month += 1;
    }
    let day = remaining_days as u64 + 1;
    (year, month, day)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// ============================================================================
// Import functionality
// ============================================================================

/// Import data from JSON format
///
/// Note: This imports metadata only. The actual AION file must be
/// recreated using the init/commit operations with the original rules.
pub fn import_json(json_data: &str) -> Result<ExportData> {
    serde_json::from_str(json_data).map_err(|e| AionError::InvalidFormat {
        reason: format!("JSON parse failed: {e}"),
    })
}

/// Import data from YAML format
pub fn import_yaml(yaml_data: &str) -> Result<ExportData> {
    serde_yaml::from_str(yaml_data).map_err(|e| AionError::InvalidFormat {
        reason: format!("YAML parse failed: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_csv_field_simple() {
        assert_eq!(escape_csv_field("hello"), "hello");
    }

    #[test]
    fn test_escape_csv_field_with_comma() {
        assert_eq!(escape_csv_field("hello, world"), "\"hello, world\"");
    }

    #[test]
    fn test_escape_csv_field_with_quotes() {
        assert_eq!(escape_csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_format_timestamp() {
        // 2024-01-01 00:00:00 UTC
        let ts = 1704067200_000_000_000u64;
        let formatted = format_timestamp_nanos(ts);
        assert!(formatted.starts_with("2024-01-01"));
    }
}
