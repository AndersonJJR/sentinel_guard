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

/// Extracts and validates a safe UTF-8 file name from `source_path`, rejecting traversal vectors.
pub fn sanitize_file_name(source_path: &Path) -> Result<String, DomainError> {
    let raw_bytes = source_path.as_os_str().as_encoded_bytes();
    if raw_bytes.is_empty() {
        return Err(DomainError::InvalidPath(
            "Source path must not be empty".to_string(),
        ));
    }

    if raw_bytes.contains(&0) {
        return Err(DomainError::PathTraversalAttempt(
            "Source path contains null byte".to_string(),
        ));
    }

    if raw_bytes.ends_with(b"/")
        || raw_bytes.ends_with(b"\\")
        || raw_bytes == b"."
        || raw_bytes.ends_with(b"/.")
        || raw_bytes.ends_with(b"\\.")
    {
        return Err(DomainError::InvalidPath(format!(
            "Source path must reference a file rather than a directory or trailing '.': {}",
            source_path.display()
        )));
    }

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
}
