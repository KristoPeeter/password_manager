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
