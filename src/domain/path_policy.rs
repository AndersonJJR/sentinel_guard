//! Pure domain path validation and system directory protection policies.

use std::path::{Component, Path};

use crate::domain::errors::DomainError;

/// Critical operating system directories that Sentinel Guard must never inspect or mutate.
pub const FORBIDDEN_SYSTEM_DIRS: &[&str] = &[
    "/etc", "/bin", "/usr", "/root", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev", "/boot",
];

/// Rejects the filesystem root `/` and any critical operating system directory prefix.
pub fn reject_forbidden_system_dir(path: &Path) -> Result<(), DomainError> {
    if path == Path::new("/") {
        return Err(DomainError::ForbiddenSystemDirectory(
            path.display().to_string(),
        ));
    }

    for forbidden in FORBIDDEN_SYSTEM_DIRS {
        if path.starts_with(forbidden) {
            return Err(DomainError::ForbiddenSystemDirectory(
                path.display().to_string(),
            ));
        }
    }

    Ok(())
}

/// Ensures that `quarantine_dir` and `approved_dir` are distinct and neither contains the other.
pub fn ensure_distinct_non_nested_dirs(
    quarantine_dir: &Path,
    approved_dir: &Path,
) -> Result<(), DomainError> {
    if quarantine_dir == approved_dir
        || approved_dir.starts_with(quarantine_dir)
        || quarantine_dir.starts_with(approved_dir)
    {
        return Err(DomainError::InvalidPath(
            "quarantine_dir and approved_dir must be distinct and must not contain each other"
                .to_string(),
        ));
    }

    Ok(())
}

/// Rejects paths that denote a directory or trailing `.` segment (`/`-suffix, `\`-suffix, `.`, `/.`, `\.`).
pub fn reject_directory_or_dot_suffix(path: &Path, label: &str) -> Result<(), DomainError> {
    let raw_bytes = path.as_os_str().as_encoded_bytes();
    if raw_bytes.ends_with(b"/")
        || raw_bytes.ends_with(b"\\")
        || raw_bytes == b"."
        || raw_bytes.ends_with(b"/.")
        || raw_bytes.ends_with(b"\\.")
    {
        return Err(DomainError::InvalidPath(format!(
            "{label} path must reference a file rather than a directory or trailing '.': {}",
            path.display()
        )));
    }

    Ok(())
}

/// Rejects empty paths (`InvalidPath`) and paths containing embedded NUL bytes (`PathTraversalAttempt`).
pub fn reject_empty_and_null_bytes(path: &Path, label: &str) -> Result<(), DomainError> {
    let raw_bytes = path.as_os_str().as_encoded_bytes();
    if raw_bytes.is_empty() {
        return Err(DomainError::InvalidPath(format!(
            "{label} path must not be empty"
        )));
    }

    if raw_bytes.contains(&0) {
        return Err(DomainError::PathTraversalAttempt(format!(
            "{label} path contains null byte"
        )));
    }

    Ok(())
}

/// Validates an absolute, non-traversal, non-system path lexically without requiring a leaf file name.
pub fn validate_absolute_non_system_path(raw_path: &Path, label: &str) -> Result<(), DomainError> {
    reject_empty_and_null_bytes(raw_path, label)?;

    if !raw_path.is_absolute() {
        return Err(DomainError::InvalidPath(format!(
            "{label} path must be absolute: {}",
            raw_path.display()
        )));
    }

    for component in raw_path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Parent directory traversal ('..') is not allowed in {label} path: {}",
                raw_path.display()
            )));
        }
    }

    reject_forbidden_system_dir(raw_path)
}

/// Validates an absolute, non-traversal, non-system file path lexically and returns its sanitized file name.
pub fn validate_absolute_non_system_file_path(
    raw_path: &Path,
    label: &str,
) -> Result<String, DomainError> {
    validate_absolute_non_system_path(raw_path, label)?;
    reject_directory_or_dot_suffix(raw_path, label)?;
    sanitize_file_name(raw_path)
}

/// Extracts and validates a safe UTF-8 file name from `source_path`, rejecting traversal vectors.
pub fn sanitize_file_name(source_path: &Path) -> Result<String, DomainError> {
    reject_empty_and_null_bytes(source_path, "Source")?;
    reject_directory_or_dot_suffix(source_path, "Source")?;

    for component in source_path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(DomainError::PathTraversalAttempt(format!(
                "Parent directory traversal ('..') is not allowed: {}",
                source_path.display()
            )));
        }
    }

    let raw_name = source_path.file_name().ok_or_else(|| {
        DomainError::InvalidPath(format!(
            "Source path does not contain a file name: {}",
            source_path.display()
        ))
    })?;

    let name = raw_name.to_str().ok_or_else(|| {
        DomainError::InvalidPath(format!(
            "File name is not valid UTF-8: {}",
            source_path.display()
        ))
    })?;

    if name.is_empty() || name == "." {
        return Err(DomainError::InvalidPath(format!(
            "Invalid file name '{name}' in path: {}",
            source_path.display()
        )));
    }

    if name == ".." {
        return Err(DomainError::PathTraversalAttempt(format!(
            "Forbidden '..' file name in path: {}",
            source_path.display()
        )));
    }

    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(DomainError::PathTraversalAttempt(format!(
            "File name contains forbidden path separator or null byte: {}",
            source_path.display()
        )));
    }

    if name.chars().any(char::is_control) {
        return Err(DomainError::InvalidPath(format!(
            "File name contains control characters: {}",
            source_path.display()
        )));
    }

    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_forbidden_system_dir_blocks_root_and_system_prefixes() {
        assert!(matches!(
            reject_forbidden_system_dir(Path::new("/")),
            Err(DomainError::ForbiddenSystemDirectory(_))
        ));
        for dir in FORBIDDEN_SYSTEM_DIRS {
            assert!(matches!(
                reject_forbidden_system_dir(Path::new(dir)),
                Err(DomainError::ForbiddenSystemDirectory(_))
            ));
            let nested = Path::new(dir).join("sub/file");
            assert!(matches!(
                reject_forbidden_system_dir(&nested),
                Err(DomainError::ForbiddenSystemDirectory(_))
            ));
        }

        assert!(reject_forbidden_system_dir(Path::new("/var/sentinel/quarantine/a.pdf")).is_ok());
        assert!(reject_forbidden_system_dir(Path::new("/tmp/etc/a.pdf")).is_ok());
    }

    #[test]
    fn reject_directory_or_dot_suffix_blocks_trailing_separators_and_dots() {
        for invalid in [
            Path::new("/tmp/eve.json/"),
            Path::new("/tmp/eve.json\\"),
            Path::new("."),
            Path::new("/tmp/eve.json/."),
            Path::new("/tmp/eve.json\\."),
        ] {
            assert!(
                matches!(
                    reject_directory_or_dot_suffix(invalid, "Test"),
                    Err(DomainError::InvalidPath(_))
                ),
                "expected InvalidPath for {}",
                invalid.display()
            );
        }

        assert!(
            reject_directory_or_dot_suffix(Path::new("/var/log/suricata/eve.json"), "Test").is_ok()
        );
    }

    #[test]
    fn validate_absolute_non_system_file_path_enforces_all_lexical_policies() {
        assert_eq!(
            validate_absolute_non_system_file_path(
                Path::new("/var/log/suricata/eve.json"),
                "Suricata eve.json"
            )
            .expect("valid absolute file path"),
            "eve.json"
        );

        for invalid in [
            Path::new(""),
            Path::new("relative/eve.json"),
            Path::new("."),
            Path::new("/tmp/eve.json/"),
            Path::new("/tmp/eve.json/."),
            Path::new("/tmp/eve\n.json"),
        ] {
            assert!(
                matches!(
                    validate_absolute_non_system_file_path(invalid, "Test"),
                    Err(DomainError::InvalidPath(_))
                ),
                "expected InvalidPath for {}",
                invalid.display()
            );
        }

        for traversal in [
            Path::new("/tmp/eve\0.json"),
            Path::new("/tmp/../eve.json"),
            Path::new("/tmp/sub\\eve.json"),
        ] {
            assert!(
                matches!(
                    validate_absolute_non_system_file_path(traversal, "Test"),
                    Err(DomainError::PathTraversalAttempt(_))
                ),
                "expected PathTraversalAttempt for {}",
                traversal.display()
            );
        }

        for forbidden in [
            Path::new("/"),
            Path::new("/etc/"),
            Path::new("/etc/passwd"),
            Path::new("/proc/1/status"),
        ] {
            assert!(
                matches!(
                    validate_absolute_non_system_file_path(forbidden, "Test"),
                    Err(DomainError::ForbiddenSystemDirectory(_))
                ),
                "expected ForbiddenSystemDirectory for {}",
                forbidden.display()
            );
        }
    }

    #[test]
    fn reject_empty_and_null_bytes_validates_raw_bytes() {
        assert!(matches!(
            reject_empty_and_null_bytes(Path::new(""), "Test"),
            Err(DomainError::InvalidPath(_))
        ));
        assert!(matches!(
            reject_empty_and_null_bytes(Path::new("/tmp/foo\0bar"), "Test"),
            Err(DomainError::PathTraversalAttempt(_))
        ));
        assert!(reject_empty_and_null_bytes(Path::new("/tmp/foo"), "Test").is_ok());
    }

    #[test]
    fn validate_absolute_non_system_path_allows_directories_and_rejects_traversal_and_system_dirs()
    {
        assert!(validate_absolute_non_system_path(Path::new("/tmp/watch_dir/"), "Watch").is_ok());
        assert!(validate_absolute_non_system_path(Path::new("/tmp/watch_dir/."), "Watch").is_ok());

        assert!(matches!(
            validate_absolute_non_system_path(Path::new("relative/dir"), "Watch"),
            Err(DomainError::InvalidPath(_))
        ));
        assert!(matches!(
            validate_absolute_non_system_path(Path::new("/tmp/../other"), "Watch"),
            Err(DomainError::PathTraversalAttempt(_))
        ));
        assert!(matches!(
            validate_absolute_non_system_path(Path::new("/tmp/a\0b"), "Watch"),
            Err(DomainError::PathTraversalAttempt(_))
        ));
        assert!(matches!(
            validate_absolute_non_system_path(Path::new("/etc/"), "Watch"),
            Err(DomainError::ForbiddenSystemDirectory(_))
        ));
    }
}
