//! Conflict Resolution Module
//!
//! Handles divergent version histories when files are modified concurrently
//! on different machines or by different authors.
//!
//! # Conflict Scenarios
//!
//! - **Fork**: Same file modified independently from same version
//! - **Divergent**: Files diverge at some point in history
//! - **Gap**: Missing versions in the chain

use crate::operations::{FileInfo, VersionInfo};

/// Conflict type detected between two file states
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConflictType {
    /// Files diverged from a common ancestor
    Divergent {
        /// Common ancestor version number
        common_ancestor: u64,
        /// Version where local diverged
        local_version: u64,
        /// Version where remote diverged
        remote_version: u64,
    },
    /// Local and remote have same version but different content
    ContentMismatch {
        /// Version number with mismatch
        version: u64,
        /// Local content hash
        local_hash: String,
        /// Remote content hash
        remote_hash: String,
    },
    /// Version gap in the chain
    VersionGap {
        /// Expected version number
        expected: u64,
        /// Actual version number found
        found: u64,
    },
    /// No conflict detected
    None,
}

impl std::fmt::Display for ConflictType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Divergent {
                common_ancestor,
                local_version,
                remote_version,
            } => {
                write!(f, "Divergent histories from version {common_ancestor}: local={local_version}, remote={remote_version}")
            }
            Self::ContentMismatch {
                version,
                local_hash,
                remote_hash,
            } => {
                write!(f, "Content mismatch at version {version}: local={local_hash}, remote={remote_hash}")
            }
            Self::VersionGap { expected, found } => {
                write!(f, "Version gap: expected {expected}, found {found}")
            }
            Self::None => write!(f, "No conflict"),
        }
    }
}

/// Conflict detection result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConflictReport {
    /// Type of conflict detected
    pub conflict_type: ConflictType,
    /// Local file info
    pub local_version_count: u64,
    /// Remote file info
    pub remote_version_count: u64,
    /// Suggested resolution strategy
    pub suggested_strategy: MergeStrategy,
}

/// Merge strategy for resolving conflicts
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MergeStrategy {
    /// Keep local version, discard remote
    KeepLocal,
    /// Keep remote version, discard local
    KeepRemote,
    /// Keep version with higher version number
    KeepNewest,
    /// Manual merge required
    Manual,
    /// Append remote versions after local (if linear)
    Append,
}

impl std::fmt::Display for MergeStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeepLocal => write!(f, "Keep local"),
            Self::KeepRemote => write!(f, "Keep remote"),
            Self::KeepNewest => write!(f, "Keep newest"),
            Self::Manual => write!(f, "Manual merge required"),
            Self::Append => write!(f, "Append remote versions"),
        }
    }
}

/// Detect conflicts between local and remote file states
///
/// # Arguments
///
/// * `local` - Local file info
/// * `remote` - Remote file info
///
/// # Returns
///
/// Conflict report with detected type and suggested strategy
pub fn detect_conflict(local: &FileInfo, remote: &FileInfo) -> ConflictReport {
    // Check if file IDs match
    if local.file_id != remote.file_id {
        return ConflictReport {
            conflict_type: ConflictType::ContentMismatch {
                version: 0,
                local_hash: format!("{:016x}", local.file_id),
                remote_hash: format!("{:016x}", remote.file_id),
            },
            local_version_count: local.version_count,
            remote_version_count: remote.version_count,
            suggested_strategy: MergeStrategy::Manual,
        };
    }

    // Check for identical files
    if local.version_count == remote.version_count {
        // Check if latest versions match
        if versions_match(local, remote) {
            return ConflictReport {
                conflict_type: ConflictType::None,
                local_version_count: local.version_count,
                remote_version_count: remote.version_count,
                suggested_strategy: MergeStrategy::KeepLocal,
            };
        }

        // Same version count but different content
        return ConflictReport {
            conflict_type: ConflictType::ContentMismatch {
                version: local.current_version,
                local_hash: format_version_hash(local),
                remote_hash: format_version_hash(remote),
            },
            local_version_count: local.version_count,
            remote_version_count: remote.version_count,
            suggested_strategy: MergeStrategy::Manual,
        };
    }

    // One has more versions - check if linear extension
    let (shorter, longer) = if local.version_count < remote.version_count {
        (local, remote)
    } else {
        (remote, local)
    };

    // Check if shorter is a prefix of longer (linear history)
    if is_linear_extension(shorter, longer) {
        let strategy = if local.version_count < remote.version_count {
            MergeStrategy::KeepRemote // Remote has more, just update to remote
        } else {
            MergeStrategy::KeepLocal // Local has more, keep local
        };

        return ConflictReport {
            conflict_type: ConflictType::None,
            local_version_count: local.version_count,
            remote_version_count: remote.version_count,
            suggested_strategy: strategy,
        };
    }

    // Divergent histories
    let common_ancestor = find_common_ancestor(local, remote);

    ConflictReport {
        conflict_type: ConflictType::Divergent {
            common_ancestor,
            local_version: local.current_version,
            remote_version: remote.current_version,
        },
        local_version_count: local.version_count,
        remote_version_count: remote.version_count,
        suggested_strategy: MergeStrategy::Manual,
    }
}

/// Check if two file states have matching latest versions
fn versions_match(local: &FileInfo, remote: &FileInfo) -> bool {
    match (local.versions.last(), remote.versions.last()) {
        (Some(l), Some(r)) => l.rules_hash == r.rules_hash,
        (None, None) => true,
        _ => false,
    }
}

/// Format version hash for display
fn format_version_hash(info: &FileInfo) -> String {
    info.versions
        .last()
        .map(|v| hex::encode(&v.rules_hash[..8]))
        .unwrap_or_else(|| "empty".to_string())
}

/// Check if shorter history is a linear prefix of longer
fn is_linear_extension(shorter: &FileInfo, longer: &FileInfo) -> bool {
    if shorter.versions.len() > longer.versions.len() {
        return false;
    }

    for (i, short_ver) in shorter.versions.iter().enumerate() {
        let Some(long_ver) = longer.versions.get(i) else {
            return false;
        };
        if short_ver.rules_hash != long_ver.rules_hash {
            return false;
        }
    }

    true
}

/// Find the common ancestor version between two divergent histories
fn find_common_ancestor(local: &FileInfo, remote: &FileInfo) -> u64 {
    let min_len = std::cmp::min(local.versions.len(), remote.versions.len());
    let mut last_matching: Option<&VersionInfo> = None;

    for i in 0..min_len {
        let (Some(l), Some(r)) = (local.versions.get(i), remote.versions.get(i)) else {
            break;
        };
        if l.rules_hash != r.rules_hash {
            return last_matching.map_or(0, |v| v.version_number);
        }
        last_matching = Some(l);
    }

    last_matching.map_or(0, |v| v.version_number)
}

/// Conflict marker for manual resolution
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConflictMarker {
    /// Marker type
    pub marker_type: MarkerType,
    /// Start position in content
    pub start: usize,
    /// End position in content
    pub end: usize,
    /// Source label
    pub source: String,
}

/// Type of conflict marker
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MarkerType {
    /// Start of conflicting section
    ConflictStart,
    /// Separator between local and remote
    Separator,
    /// End of conflicting section
    ConflictEnd,
}

/// Create conflict markers for manual merge
///
/// Format similar to git merge conflicts:
/// ```text
/// <<<<<<< LOCAL
/// local content
/// =======
/// remote content
/// >>>>>>> REMOTE
/// ```
pub fn create_conflict_markers(
    local_content: &[u8],
    remote_content: &[u8],
    local_label: &str,
    remote_label: &str,
) -> Vec<u8> {
    let mut result = Vec::new();

    // Start marker
    result.extend_from_slice(b"<<<<<<< ");
    result.extend_from_slice(local_label.as_bytes());
    result.push(b'\n');

    // Local content
    result.extend_from_slice(local_content);
    if !local_content.ends_with(b"\n") {
        result.push(b'\n');
    }

    // Separator
    result.extend_from_slice(b"=======\n");

    // Remote content
    result.extend_from_slice(remote_content);
    if !remote_content.ends_with(b"\n") {
        result.push(b'\n');
    }

    // End marker
    result.extend_from_slice(b">>>>>>> ");
    result.extend_from_slice(remote_label.as_bytes());
    result.push(b'\n');

    result
}

/// Check if content contains conflict markers
pub fn has_conflict_markers(content: &[u8]) -> bool {
    let content_str = String::from_utf8_lossy(content);
    content_str.contains("<<<<<<<") && content_str.contains(">>>>>>>")
}

/// Parse conflict markers from content
///
/// Returns (local_content, remote_content) if markers found
pub fn parse_conflict_markers(content: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let content_str = String::from_utf8_lossy(content);

    let start_idx = content_str.find("<<<<<<< ")?;
    let separator_idx = content_str.find("=======")?;
    let end_idx = content_str.find(">>>>>>> ")?;

    if start_idx >= separator_idx || separator_idx >= end_idx {
        return None;
    }

    // Extract local content (after first newline, before separator)
    let after_start = content_str[start_idx..].find('\n')? + start_idx + 1;
    let local = &content_str[after_start..separator_idx];

    // Extract remote content (after separator newline, before end)
    let after_sep = separator_idx + 8; // "=======\n"
    let remote = &content_str[after_sep..end_idx];

    Some((
        local.trim_end().as_bytes().to_vec(),
        remote.trim_end().as_bytes().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_markers() {
        let local = b"local version";
        let remote = b"remote version";

        let merged = create_conflict_markers(local, remote, "LOCAL", "REMOTE");

        assert!(has_conflict_markers(&merged));

        let (parsed_local, parsed_remote) =
            parse_conflict_markers(&merged).unwrap_or_else(|| std::process::abort());
        assert_eq!(parsed_local, local.to_vec());
        assert_eq!(parsed_remote, remote.to_vec());
    }

    #[test]
    fn test_no_conflict_markers() {
        let content = b"normal content without markers";
        assert!(!has_conflict_markers(content));
    }

    #[test]
    fn test_merge_strategy_display() {
        assert_eq!(MergeStrategy::KeepLocal.to_string(), "Keep local");
        assert_eq!(MergeStrategy::Manual.to_string(), "Manual merge required");
    }

    #[test]
    fn test_conflict_type_display() {
        let conflict = ConflictType::Divergent {
            common_ancestor: 5,
            local_version: 7,
            remote_version: 8,
        };
        let display = conflict.to_string();
        assert!(display.contains("Divergent"));
        assert!(display.contains("5"));
    }
}
