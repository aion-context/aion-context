//! String table for AION v2 file format
//!
//! This module implements the null-terminated UTF-8 string table as specified
//! in RFC-0002 Section 5.5. The string table is used to store variable-length
//! text data such as commit messages, audit details, and metadata.
//!
//! # Format
//!
//! The string table is a concatenation of null-terminated UTF-8 strings with
//! no padding between entries:
//!
//! ```text
//! "Genesis version\0Added fraud detection\0Updated rules\0"
//! ```
//!
//! # Rules (RFC-0002)
//!
//! 1. All strings are UTF-8 encoded
//! 2. Each string terminated with single null byte (0x00)
//! 3. No padding between strings
//! 4. Offsets point to first character (not null terminator)
//! 5. Lengths do NOT include null terminator
//!
//! # Building String Tables
//!
//! Use [`StringTableBuilder`] to construct string tables during serialization:
//!
//! ```
//! use aion_context::string_table::StringTableBuilder;
//!
//! let mut builder = StringTableBuilder::new();
//!
//! // Add strings and get their (offset, length)
//! let (offset1, len1) = builder.add("Genesis version");
//! let (offset2, len2) = builder.add("Added fraud detection");
//!
//! // Build final byte array
//! let bytes = builder.build();
//!
//! assert_eq!(offset1, 0);
//! assert_eq!(len1, 15);
//! assert_eq!(offset2, 16); // "Genesis version\0" = 16 bytes
//! assert_eq!(len2, 21);
//! ```
//!
//! # Parsing String Tables
//!
//! Use [`StringTable`] for zero-copy parsing during deserialization:
//!
//! ```
//! use aion_context::string_table::StringTable;
//!
//! let data = b"Genesis version\0Added fraud detection\0";
//! let table = StringTable::new(data).unwrap();
//!
//! // Extract strings by offset/length
//! let s1 = table.get(0, 15).unwrap();
//! assert_eq!(s1, "Genesis version");
//!
//! let s2 = table.get(16, 21).unwrap();
//! assert_eq!(s2, "Added fraud detection");
//! ```
//!
//! # UTF-8 Validation
//!
//! All strings are validated as UTF-8:
//! - During construction (when added to builder)
//! - During parsing (when table is created)
//! - During extraction (when strings are retrieved)
//!
//! Invalid UTF-8 sequences return [`AionError::InvalidUtf8`].

use crate::{AionError, Result};

/// String table builder for constructing string tables during serialization
///
/// This builder accumulates strings and tracks their offsets/lengths.
/// Strings are automatically null-terminated and concatenated with no padding.
///
/// # Examples
///
/// ```
/// use aion_context::string_table::StringTableBuilder;
///
/// let mut builder = StringTableBuilder::new();
///
/// let (offset, length) = builder.add("Hello, world!");
/// assert_eq!(offset, 0);
/// assert_eq!(length, 13);
///
/// let bytes = builder.build();
/// assert_eq!(bytes, b"Hello, world!\0");
/// ```
#[derive(Debug, Clone, Default)]
pub struct StringTableBuilder {
    /// Accumulated string data (null-terminated)
    data: Vec<u8>,
}

impl StringTableBuilder {
    /// Create a new empty string table builder
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTableBuilder;
    ///
    /// let builder = StringTableBuilder::new();
    /// assert_eq!(builder.len(), 0);
    /// assert!(builder.is_empty());
    /// ```
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::new() not const in MSRV 1.70
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create a builder with pre-allocated capacity
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTableBuilder;
    ///
    /// let builder = StringTableBuilder::with_capacity(1024);
    /// assert_eq!(builder.len(), 0);
    /// ```
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Add a string to the table
    ///
    /// Returns `(offset, length)` where:
    /// - `offset` is the byte offset of the string's first character
    /// - `length` is the string length in bytes (excluding null terminator)
    ///
    /// The string is automatically null-terminated and appended to the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTableBuilder;
    ///
    /// let mut builder = StringTableBuilder::new();
    ///
    /// let (offset1, len1) = builder.add("First");
    /// assert_eq!(offset1, 0);
    /// assert_eq!(len1, 5);
    ///
    /// let (offset2, len2) = builder.add("Second");
    /// assert_eq!(offset2, 6); // "First\0" = 6 bytes
    /// assert_eq!(len2, 6);
    /// ```
    #[allow(clippy::cast_possible_truncation)] // String lengths capped by u32::MAX
    pub fn add(&mut self, s: &str) -> (u64, u32) {
        let offset = self.data.len() as u64;
        let length = s.len() as u32;

        // Append string bytes
        self.data.extend_from_slice(s.as_bytes());

        // Append null terminator
        self.data.push(0);

        (offset, length)
    }

    /// Get the current total size in bytes
    ///
    /// This includes all strings and their null terminators.
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTableBuilder;
    ///
    /// let mut builder = StringTableBuilder::new();
    /// assert_eq!(builder.len(), 0);
    ///
    /// builder.add("Hello");
    /// assert_eq!(builder.len(), 6); // "Hello\0"
    ///
    /// builder.add("World");
    /// assert_eq!(builder.len(), 12); // "Hello\0World\0"
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the table is empty
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTableBuilder;
    ///
    /// let mut builder = StringTableBuilder::new();
    /// assert!(builder.is_empty());
    ///
    /// builder.add("Test");
    /// assert!(!builder.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Build the final string table as a byte vector
    ///
    /// Returns the complete string table with all null terminators.
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTableBuilder;
    ///
    /// let mut builder = StringTableBuilder::new();
    /// builder.add("Alpha");
    /// builder.add("Beta");
    ///
    /// let bytes = builder.build();
    /// assert_eq!(bytes, b"Alpha\0Beta\0");
    /// ```
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        self.data
    }

    /// Clear all strings from the builder
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTableBuilder;
    ///
    /// let mut builder = StringTableBuilder::new();
    /// builder.add("Test");
    /// assert!(!builder.is_empty());
    ///
    /// builder.clear();
    /// assert!(builder.is_empty());
    /// ```
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

/// String table for zero-copy parsing of string data
///
/// This struct wraps a byte slice containing null-terminated UTF-8 strings.
/// Strings can be extracted by offset and length without copying.
///
/// # Examples
///
/// ```
/// use aion_context::string_table::StringTable;
///
/// let data = b"Genesis\0Version 2\0";
/// let table = StringTable::new(data).unwrap();
///
/// let s1 = table.get(0, 7).unwrap();
/// assert_eq!(s1, "Genesis");
///
/// let s2 = table.get(8, 9).unwrap();
/// assert_eq!(s2, "Version 2");
/// ```
#[derive(Debug, Clone, Copy)]
pub struct StringTable<'a> {
    /// Raw byte data containing null-terminated strings
    data: &'a [u8],
}

impl<'a> StringTable<'a> {
    /// Create a new string table from byte data
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The data contains invalid UTF-8 sequences
    /// - The data is not properly null-terminated
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTable;
    ///
    /// let data = b"Hello\0World\0";
    /// let table = StringTable::new(data).unwrap();
    /// ```
    pub fn new(data: &'a [u8]) -> Result<Self> {
        // Validate that data contains valid UTF-8
        // We do this by attempting to convert to str
        std::str::from_utf8(data).map_err(|e| AionError::InvalidUtf8 {
            reason: format!("String table contains invalid UTF-8: {e}"),
        })?;

        Ok(Self { data })
    }

    /// Get a string by offset and length
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset to the first character of the string
    /// * `length` - Length of the string in bytes (excluding null terminator)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Offset + length exceeds table bounds
    /// - The extracted bytes are not valid UTF-8
    /// - The string is not properly null-terminated
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTable;
    ///
    /// let data = b"First\0Second\0Third\0";
    /// let table = StringTable::new(data).unwrap();
    ///
    /// assert_eq!(table.get(0, 5).unwrap(), "First");
    /// assert_eq!(table.get(6, 6).unwrap(), "Second");
    /// assert_eq!(table.get(13, 5).unwrap(), "Third");
    /// ```
    #[allow(clippy::cast_possible_truncation)] // u64 to usize for indexing
    pub fn get(&self, offset: u64, length: u32) -> Result<&'a str> {
        let offset = offset as usize;
        let length = length as usize;

        // Check bounds
        let end = offset
            .checked_add(length)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: format!("String table access overflow: offset={offset}, length={length}"),
            })?;

        if end > self.data.len() {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "String table access out of bounds: offset={offset}, length={length}, table_size={}",
                    self.data.len()
                ),
            });
        }

        // Extract string bytes (excluding null terminator)
        let string_bytes = self
            .data
            .get(offset..end)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: format!("Failed to extract string at offset {offset}"),
            })?;

        // Verify null terminator is present
        if end < self.data.len() {
            if let Some(&byte) = self.data.get(end) {
                if byte != 0 {
                    return Err(AionError::InvalidFormat {
                        reason: format!("String at offset {offset} is not null-terminated"),
                    });
                }
            }
        }

        // Convert to UTF-8 string
        std::str::from_utf8(string_bytes).map_err(|e| AionError::InvalidUtf8 {
            reason: format!("String at offset {offset} contains invalid UTF-8: {e}"),
        })
    }

    /// Get total size of the string table in bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTable;
    ///
    /// let data = b"Alpha\0Beta\0";
    /// let table = StringTable::new(data).unwrap();
    /// assert_eq!(table.len(), 11);
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the string table is empty
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTable;
    ///
    /// let empty = StringTable::new(b"").unwrap();
    /// assert!(empty.is_empty());
    ///
    /// let non_empty = StringTable::new(b"Test\0").unwrap();
    /// assert!(!non_empty.is_empty());
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the raw byte data
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::string_table::StringTable;
    ///
    /// let data = b"Hello\0";
    /// let table = StringTable::new(data).unwrap();
    /// assert_eq!(table.as_bytes(), b"Hello\0");
    /// ```
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in test code
mod tests {
    use super::*;

    mod builder {
        use super::*;

        #[test]
        fn should_create_empty_builder() {
            let builder = StringTableBuilder::new();
            assert_eq!(builder.len(), 0);
            assert!(builder.is_empty());
        }

        #[test]
        fn should_add_single_string() {
            let mut builder = StringTableBuilder::new();
            let (offset, length) = builder.add("Hello");

            assert_eq!(offset, 0);
            assert_eq!(length, 5);
            assert_eq!(builder.len(), 6); // "Hello\0"

            let bytes = builder.build();
            assert_eq!(bytes, b"Hello\0");
        }

        #[test]
        fn should_add_multiple_strings() {
            let mut builder = StringTableBuilder::new();

            let (offset1, len1) = builder.add("First");
            assert_eq!(offset1, 0);
            assert_eq!(len1, 5);

            let (offset2, len2) = builder.add("Second");
            assert_eq!(offset2, 6);
            assert_eq!(len2, 6);

            let (offset3, len3) = builder.add("Third");
            assert_eq!(offset3, 13);
            assert_eq!(len3, 5);

            let bytes = builder.build();
            assert_eq!(bytes, b"First\0Second\0Third\0");
        }

        #[test]
        fn should_handle_empty_strings() {
            let mut builder = StringTableBuilder::new();
            let (offset, length) = builder.add("");

            assert_eq!(offset, 0);
            assert_eq!(length, 0);
            assert_eq!(builder.len(), 1); // Just null terminator

            let bytes = builder.build();
            assert_eq!(bytes, b"\0");
        }

        #[test]
        fn should_handle_utf8_strings() {
            let mut builder = StringTableBuilder::new();

            builder.add("Hello 世界");
            builder.add("Γειά σου κόσμε");
            builder.add("🎉🎊");

            let bytes = builder.build();
            let expected = "Hello 世界\0Γειά σου κόσμε\0🎉🎊\0";
            assert_eq!(bytes, expected.as_bytes());
        }

        #[test]
        fn should_handle_special_characters() {
            let mut builder = StringTableBuilder::new();
            builder.add("Line1\nLine2");
            builder.add("Tab\there");
            builder.add("Quote\"Test");

            let bytes = builder.build();
            assert_eq!(bytes, b"Line1\nLine2\0Tab\there\0Quote\"Test\0");
        }

        #[test]
        fn should_create_with_capacity() {
            let builder = StringTableBuilder::with_capacity(1024);
            assert_eq!(builder.len(), 0);
            assert!(builder.is_empty());
        }

        #[test]
        fn should_clear_builder() {
            let mut builder = StringTableBuilder::new();
            builder.add("Test");
            assert_eq!(builder.len(), 5);

            builder.clear();
            assert_eq!(builder.len(), 0);
            assert!(builder.is_empty());
        }

        #[test]
        fn should_track_offsets_correctly() {
            let mut builder = StringTableBuilder::new();

            let strings = vec![
                "Genesis version",
                "Added fraud detection",
                "Updated compliance rules",
            ];

            let mut expected_offset = 0u64;
            for s in &strings {
                let (offset, length) = builder.add(s);
                assert_eq!(offset, expected_offset);
                assert_eq!(length as usize, s.len());
                expected_offset += s.len() as u64 + 1; // +1 for null terminator
            }
        }
    }

    mod parser {
        use super::*;

        #[test]
        fn should_parse_empty_table() {
            let table = StringTable::new(b"").unwrap();
            assert_eq!(table.len(), 0);
            assert!(table.is_empty());
        }

        #[test]
        fn should_parse_single_string() {
            let data = b"Hello\0";
            let table = StringTable::new(data).unwrap();

            let s = table.get(0, 5).unwrap();
            assert_eq!(s, "Hello");
        }

        #[test]
        fn should_parse_multiple_strings() {
            let data = b"First\0Second\0Third\0";
            let table = StringTable::new(data).unwrap();

            assert_eq!(table.get(0, 5).unwrap(), "First");
            assert_eq!(table.get(6, 6).unwrap(), "Second");
            assert_eq!(table.get(13, 5).unwrap(), "Third");
        }

        #[test]
        fn should_handle_empty_string() {
            let data = b"\0Test\0";
            let table = StringTable::new(data).unwrap();

            assert_eq!(table.get(0, 0).unwrap(), "");
            assert_eq!(table.get(1, 4).unwrap(), "Test");
        }

        #[test]
        fn should_parse_utf8_strings() {
            let s1 = "Hello 世界";
            let s2 = "🎉";
            let data = format!("{s1}\0{s2}\0");
            let table = StringTable::new(data.as_bytes()).unwrap();

            #[allow(clippy::cast_possible_truncation)]
            let len1 = s1.len() as u32;
            #[allow(clippy::cast_possible_truncation)]
            let len2 = s2.len() as u32;
            let offset2 = u64::from(len1 + 1); // +1 for null terminator

            assert_eq!(table.get(0, len1).unwrap(), s1);
            assert_eq!(table.get(offset2, len2).unwrap(), s2);
        }

        #[test]
        fn should_reject_invalid_utf8() {
            let data = b"Hello\0\xFF\xFE\0"; // Invalid UTF-8
            let result = StringTable::new(data);
            assert!(result.is_err());
        }

        #[test]
        fn should_reject_out_of_bounds_access() {
            let data = b"Test\0";
            let table = StringTable::new(data).unwrap();

            // Offset beyond bounds
            let result = table.get(100, 5);
            assert!(result.is_err());

            // Length exceeds bounds
            let result = table.get(0, 100);
            assert!(result.is_err());
        }

        #[test]
        fn should_verify_null_terminator() {
            let data = b"Hello\0World\0";
            let table = StringTable::new(data).unwrap();

            // Valid: properly null-terminated
            assert!(table.get(0, 5).is_ok());

            // Invalid: wrong length (would miss null terminator)
            let result = table.get(0, 10);
            assert!(result.is_err());
        }

        #[test]
        fn should_get_as_bytes() {
            let data = b"Test\0";
            let table = StringTable::new(data).unwrap();
            assert_eq!(table.as_bytes(), b"Test\0");
        }
    }

    mod roundtrip {
        use super::*;

        #[test]
        fn should_roundtrip_single_string() {
            let mut builder = StringTableBuilder::new();
            let (offset, length) = builder.add("Test string");

            let bytes = builder.build();
            let table = StringTable::new(&bytes).unwrap();

            let recovered = table.get(offset, length).unwrap();
            assert_eq!(recovered, "Test string");
        }

        #[test]
        fn should_roundtrip_multiple_strings() {
            let mut builder = StringTableBuilder::new();

            let strings = vec![
                "Genesis version",
                "Added fraud detection",
                "Updated compliance rules",
                "Fixed security vulnerability",
            ];

            let mut entries = Vec::new();
            for s in &strings {
                entries.push(builder.add(s));
            }

            let bytes = builder.build();
            let table = StringTable::new(&bytes).unwrap();

            for ((offset, length), expected) in entries.iter().zip(&strings) {
                let recovered = table.get(*offset, *length).unwrap();
                assert_eq!(recovered, *expected);
            }
        }

        #[test]
        fn should_roundtrip_utf8() {
            let mut builder = StringTableBuilder::new();

            let strings = vec!["Hello 世界", "Γειά σου κόσμε", "مرحبا بالعالم", "🎉🎊🎈"];

            let mut entries = Vec::new();
            for s in &strings {
                entries.push(builder.add(s));
            }

            let bytes = builder.build();
            let table = StringTable::new(&bytes).unwrap();

            for ((offset, length), expected) in entries.iter().zip(&strings) {
                let recovered = table.get(*offset, *length).unwrap();
                assert_eq!(recovered, *expected);
            }
        }

        #[test]
        fn should_roundtrip_empty_string() {
            let mut builder = StringTableBuilder::new();
            let (offset, length) = builder.add("");

            let bytes = builder.build();
            let table = StringTable::new(&bytes).unwrap();

            let recovered = table.get(offset, length).unwrap();
            assert_eq!(recovered, "");
        }
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_add_get_roundtrip(tc: hegel::TestCase) {
            let strings = tc.draw(gs::vecs(gs::text().max_size(64)).min_size(1).max_size(16));
            let mut builder = StringTableBuilder::new();
            let handles: Vec<(u64, u32)> = strings.iter().map(|s| builder.add(s)).collect();
            let bytes = builder.build();
            let table = StringTable::new(&bytes).unwrap_or_else(|_| std::process::abort());
            for (original, (offset, length)) in strings.iter().zip(handles.iter()) {
                let recovered = table
                    .get(*offset, *length)
                    .unwrap_or_else(|_| std::process::abort());
                assert_eq!(recovered, original.as_str());
            }
        }

        #[hegel::test]
        fn prop_builder_len_strictly_increases_on_add(tc: hegel::TestCase) {
            let strings = tc.draw(gs::vecs(gs::text().max_size(64)).min_size(1).max_size(16));
            let mut builder = StringTableBuilder::new();
            let mut prev = builder.len();
            for s in &strings {
                builder.add(s);
                let now = builder.len();
                assert!(now > prev);
                prev = now;
            }
        }
    }
}
