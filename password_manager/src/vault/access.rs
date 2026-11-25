use std::{fmt, io, path::Path};

// which rule a path broke. the order of the variants is the order the checks run in
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AccessCheck {
    Symlink,
    Type,
    Owner,
    Mode,
}

impl AccessCheck {
    // the name that goes into the log
    #[allow(dead_code)] // audit log, task 8
    pub fn as_str(self) -> &'static str {
        match self {
            AccessCheck::Symlink => "symlink",
            AccessCheck::Type => "type",
            AccessCheck::Owner => "owner",
            AccessCheck::Mode => "mode",
        }
    }
}

#[derive(Debug)]
pub enum AccessError {
    Denied(AccessCheck),
    Io(io::Error),
}

impl fmt::Display for AccessError {
    // generic on purpose: which check failed goes to the log, not the screen
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessError::Denied(_) => write!(f, "Access denied"),
            AccessError::Io(_) => write!(f, "Could not access vault files"),
        }
    }
}

impl std::error::Error for AccessError {}

impl From<io::Error> for AccessError {
    fn from(e: io::Error) -> Self {
        AccessError::Io(e)
    }
}

pub fn check_dir(path: &Path) -> Result<(), AccessError> {
    check(path, true)
}

pub fn check_file(path: &Path) -> Result<(), AccessError> {
    check(path, false)
}

#[cfg(unix)]
fn check(path: &Path, expect_dir: bool) -> Result<(), AccessError> {
    use std::os::unix::fs::MetadataExt;
    // symlink_metadata describes the link itself; plain metadata would follow it and check whatever it points to instead
    let meta = std::fs::symlink_metadata(path)?;
    let file_type = meta.file_type();
    let is_expected_type = if expect_dir {
        file_type.is_dir()
    } else {
        file_type.is_file()
    };
    evaluate(
        file_type.is_symlink(),
        is_expected_type,
        meta.uid(),
        rustix::process::geteuid().as_raw(),
        meta.mode(),
    )
    .map_err(AccessError::Denied)
}

// windows has no unix owner or mode bits. ACL is not checked
fn check(_path: &Path, _expect_dir: bool) -> Result<(), AccessError> {
    Ok(())
}

// kept free of the filesystem so every branch can be tested, including a foreign owner, which would otherwise need root to set up
fn evaluate(
    is_symlink: bool,
    is_expected_type: bool,
    file_uid: u32,
    process_uid: u32,
    mode: u32,
) -> Result<(), AccessCheck> {
    if is_symlink {
        Err(AccessCheck::Symlink)
    } else if !is_expected_type {
        Err(AccessCheck::Type)
    } else if file_uid != process_uid {
        Err(AccessCheck::Owner)
    } else if mode & 0o077 != 0 {
        // any read, write or execute bit for group or others
        Err(AccessCheck::Mode)
    } else {
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn file_with_mode(dir: &tempfile::TempDir, mode: u32) -> PathBuf {
        let path = dir.path().join("vault.json");
        fs::write(&path, "{}").unwrap();
        set_mode(&path, mode);
        path
    }

    fn dir_with_mode(dir: &tempfile::TempDir, mode: u32) -> PathBuf {
        let path = dir.path().join("alice");
        fs::create_dir(&path).unwrap();
        set_mode(&path, mode);
        path
    }

    fn denied(result: Result<(), AccessError>) -> Option<AccessCheck> {
        match result {
            Err(AccessError::Denied(check)) => Some(check),
            _ => None,
        }
    }

    // what the app itself creates must always pass
    #[test]
    fn owner_only_file_and_dir_pass() {
        let dir = tempfile::tempdir().unwrap();

        assert!(check_file(&file_with_mode(&dir, 0o600)).is_ok());
        assert!(check_dir(&dir_with_mode(&dir, 0o700)).is_ok());
    }

    // any read, write or execute bit for group or others means someone else can get at the vault
    #[test]
    fn group_or_world_bits_fail_mode() {
        for mode in [0o640, 0o604, 0o660, 0o644] {
            let dir = tempfile::tempdir().unwrap();
            let file = file_with_mode(&dir, mode);
            assert_eq!(
                denied(check_file(&file)),
                Some(AccessCheck::Mode),
                "{mode:o}"
            );
        }
        for mode in [0o750, 0o705] {
            let dir = tempfile::tempdir().unwrap();
            let folder = dir_with_mode(&dir, mode);
            assert_eq!(
                denied(check_dir(&folder)),
                Some(AccessCheck::Mode),
                "{mode:o}"
            );
            set_mode(&folder, 0o700); // so the temp dir can be cleaned up
        }
    }

    // a symlink could point anywhere later, so it is refused even when today's target is fine
    #[test]
    fn symlink_fails_even_to_a_good_target() {
        let dir = tempfile::tempdir().unwrap();
        let file = file_with_mode(&dir, 0o600);
        let folder = dir_with_mode(&dir, 0o700);
        let file_link = dir.path().join("file-link");
        let dir_link = dir.path().join("dir-link");
        symlink(&file, &file_link).unwrap();
        symlink(&folder, &dir_link).unwrap();

        assert_eq!(denied(check_file(&file_link)), Some(AccessCheck::Symlink));
        assert_eq!(denied(check_dir(&dir_link)), Some(AccessCheck::Symlink));
    }

    // a folder where the vault should be, or a file where the user folder should be
    #[test]
    fn wrong_type_fails() {
        let dir = tempfile::tempdir().unwrap();
        let file = file_with_mode(&dir, 0o600);
        let folder = dir_with_mode(&dir, 0o700);

        assert_eq!(denied(check_file(&folder)), Some(AccessCheck::Type));
        assert_eq!(denied(check_dir(&file)), Some(AccessCheck::Type));
    }

    // creating a file owned by someone else needs root, so the owner rule is tested directly
    #[test]
    fn foreign_owner_fails() {
        assert_eq!(
            evaluate(false, true, 1000, 1001, 0o600),
            Err(AccessCheck::Owner)
        );
        assert_eq!(evaluate(false, true, 1000, 1000, 0o600), Ok(()));
    }

    // the log records which check failed, so the order has to be fixed
    #[test]
    fn first_failing_check_is_reported() {
        assert_eq!(
            evaluate(true, false, 1, 2, 0o777),
            Err(AccessCheck::Symlink)
        );
        assert_eq!(evaluate(false, false, 1, 2, 0o777), Err(AccessCheck::Type));
        assert_eq!(evaluate(false, true, 1, 2, 0o777), Err(AccessCheck::Owner));
        assert_eq!(evaluate(false, true, 1, 1, 0o777), Err(AccessCheck::Mode));
    }

    // a missing vault means "no such user", which the login flow handles; it is not an attack
    #[test]
    fn missing_path_is_io_not_denied() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");

        for result in [check_file(&missing), check_dir(&missing)] {
            assert!(
                matches!(result, Err(AccessError::Io(ref e)) if e.kind() == io::ErrorKind::NotFound)
            );
        }
    }
}
