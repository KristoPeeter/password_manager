// nothing uses this module outside its tests until the login flow is wired in (tasks 5 and 7)
#![allow(dead_code)]

use std::{
    ffi::OsString,
    fmt, fs, io,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

const MAX_USERNAME_LEN: usize = 32;
const ENV_OVERRIDE: &str = "SECUREVAULT_HOME";
const APP_FOLDER: &str = "securevault";
const USERS_FOLDER: &str = "users";

// the private field means the only way to get a Username is through parse,
// so every user path is built from a validated name
pub struct Username(String);

#[derive(Debug, PartialEq)]
pub struct UsernameError;

impl fmt::Display for UsernameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid username")
    }
}

impl std::error::Error for UsernameError {}

impl Username {
    // a whitelist, not a blacklist: only a-z, 0-9, '-' and '_' can appear. Sorry Jüri you're Juri now
    pub fn parse(input: &str) -> Result<Self, UsernameError> {
        let mut chars = input.chars();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let rest_ok =
            chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        // all allowed characters are one byte, so the byte length is the character count
        if first_ok && rest_ok && input.len() <= MAX_USERNAME_LEN {
            Ok(Self(input.to_owned()))
        } else {
            Err(UsernameError)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub enum PathsError {
    NoHome,
    NotAbsolute,
}

impl fmt::Display for PathsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathsError::NoHome => write!(f, "Couldn't find a folder to store data in"),
            PathsError::NotAbsolute => write!(f, "{ENV_OVERRIDE} must be an absolute path"),
        }
    }
}

impl std::error::Error for PathsError {}

pub struct DataDir(PathBuf);

impl DataDir {
    pub fn resolve() -> Result<Self, PathsError> {
        Self::resolve_from(std::env::var_os(ENV_OVERRIDE), dirs::data_dir())
    }

    pub(crate) fn resolve_from(
        env: Option<OsString>,
        default: Option<PathBuf>,
    ) -> Result<Self, PathsError> {
        match env {
            Some(value) => {
                let base = PathBuf::from(value);
                if base.is_absolute() {
                    Ok(Self(base))
                } else {
                    Err(PathsError::NotAbsolute)
                }
            }
            None => default
                .map(|dir| Self(dir.join(APP_FOLDER)))
                .ok_or(PathsError::NoHome),
        }
    }

    pub fn at(base: PathBuf) -> Self {
        Self(base)
    }

    pub fn ensure(&self) -> io::Result<()> {
        create_private_dir(&self.0)?;
        create_private_dir(&self.users_dir())
    }

    fn users_dir(&self) -> PathBuf {
        self.0.join(USERS_FOLDER)
    }

    // the only function that turns a username into a path
    pub fn user_dir(&self, user: &Username) -> PathBuf {
        self.users_dir().join(user.as_str())
    }

    pub fn vault_file(&self, user: &Username) -> PathBuf {
        self.user_dir(user).join("vault.json")
    }

    pub fn attempts_file(&self, user: &Username) -> PathBuf {
        self.user_dir(user).join("attempts.json")
    }

    pub fn lock_file(&self, user: &Username) -> PathBuf {
        self.user_dir(user).join("lock")
    }

    pub fn seal_file(&self, user: &Username) -> PathBuf {
        self.user_dir(user).join("log.seal")
    }

    pub fn log_file(&self) -> PathBuf {
        self.0.join("events.log")
    }

    pub fn rotated_log_file(&self) -> PathBuf {
        self.0.join("events.log.1")
    }
}

// created with 0700 from the start, so there is no moment where another user could read it.
// an existing folder is left as it is: the access checks (task 4) refuse loose permissions
// instead of quietly fixing them
fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(path)?;
    // recursive create skips folders that already exist, so make sure this one is really a folder
    if fs::metadata(path)?.is_dir() {
        Ok(())
    } else {
        Err(io::Error::other("not a folder"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn base(data: &DataDir) -> &Path {
        &data.0
    }

    // the shortest, a typical one, every allowed symbol, and the longest allowed
    #[test]
    fn accepts_valid_usernames() {
        let max = "a".repeat(32);
        for name in ["a", "alice", "a-b_c9", "9lives", max.as_str()] {
            let user = Username::parse(name).unwrap_or_else(|_| panic!("{name:?} rejected"));
            assert_eq!(user.as_str(), name);
        }
    }

    // anything that could escape the users folder, collide on a case-insensitive disk,
    // look like another name, or confuse a terminal is refused
    #[test]
    fn rejects_bad_usernames() {
        let too_long = "a".repeat(33);
        for name in [
            "",
            too_long.as_str(),
            "Alice",
            "-alice",
            "_alice",
            "../x",
            "a/b",
            "a\\b",
            ".",
            "..",
            "a b",
            "a.b",
            "ä",
            "а", // cyrillic, looks like latin a
            "a\0b",
            "a\n",
        ] {
            assert_eq!(
                Username::parse(name).err(),
                Some(UsernameError),
                "{name:?} accepted"
            );
        }
    }

    // every per-user file lands in that user's own folder and nowhere else
    #[test]
    fn user_paths_stay_inside_users_folder() {
        let data = DataDir::at(PathBuf::from("/base"));
        let user = Username::parse("alice").unwrap();
        let folder = Path::new("/base/users/alice");

        assert_eq!(data.user_dir(&user), folder);
        for file in UserFile::ALL {
            let path = data.user_file(&user, file);
            assert_eq!(path.parent(), Some(folder), "{file:?} outside user folder");
        }
        assert_eq!(
            data.user_file(&user, UserFile::Vault),
            folder.join("vault.json")
        );
    }

    // the shared log lives in the base folder, not inside any one user's folder
    #[test]
    fn log_files_live_in_base_folder() {
        let data = DataDir::at(PathBuf::from("/base"));

        assert_eq!(data.log_file(), Path::new("/base/events.log"));
        assert_eq!(data.rotated_log_file(), Path::new("/base/events.log.1"));
    }

    // a relative override would depend on whatever folder the app was started from
    #[test]
    fn env_override_must_be_absolute() {
        let relative = DataDir::resolve_from(Some("rel/dir".into()), Some("/x".into()));
        assert_eq!(relative.err(), Some(PathsError::NotAbsolute));

        let empty = DataDir::resolve_from(Some("".into()), Some("/x".into()));
        assert_eq!(empty.err(), Some(PathsError::NotAbsolute));

        let absolute = DataDir::resolve_from(Some("/abs/dir".into()), Some("/x".into())).unwrap();
        assert_eq!(base(&absolute), Path::new("/abs/dir"));
    }

    #[test]
    fn default_is_data_dir_securevault() {
        let data = DataDir::resolve_from(None, Some("/x".into())).unwrap();

        assert_eq!(base(&data), Path::new("/x/securevault"));
    }

    // no HOME (some services, containers) must give a clean error, not a crash
    #[test]
    fn no_home_is_an_error_not_a_panic() {
        assert_eq!(
            DataDir::resolve_from(None, None).err(),
            Some(PathsError::NoHome)
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_creates_owner_only_folders() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let data = DataDir::at(dir.path().join("securevault"));

        data.ensure().unwrap();

        for folder in [base(&data).to_path_buf(), base(&data).join("users")] {
            let meta = std::fs::metadata(&folder).unwrap();
            assert!(meta.is_dir(), "{folder:?} missing");
            assert_eq!(meta.permissions().mode() & 0o777, 0o700, "{folder:?}");
        }
    }

    // an existing data folder others can get into is refused, not quietly kept or fixed:
    // SECUREVAULT_HOME may point at a folder someone else prepared
    #[cfg(unix)]
    #[test]
    fn ensure_refuses_loose_existing_folders() {
        use std::os::unix::fs::PermissionsExt;
        for folder in ["", "users"] {
            for mode in [0o755, 0o775, 0o777] {
                let dir = tempfile::tempdir().unwrap();
                let data = DataDir::at(dir.path().join("securevault"));
                data.ensure().unwrap();
                let path = base(&data).join(folder);
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();

                assert!(data.ensure().is_err(), "{folder:?} {mode:o} accepted");
                let now = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(now & 0o777, mode, "{folder:?} {mode:o} was changed");
            }
        }
    }

    // a symlinked data folder or users/ could be repointed later, so it is refused even when
    // today's target looks fine
    #[cfg(unix)]
    #[test]
    fn ensure_refuses_symlinked_folders() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = DataDir::at(dir.path().join("real"));
        real.ensure().unwrap();

        // the data folder is a link
        let link = dir.path().join("link");
        symlink(base(&real), &link).unwrap();
        assert!(DataDir::at(link).ensure().is_err(), "symlinked base accepted");

        // users/ is a link
        let data = DataDir::at(dir.path().join("securevault"));
        data.ensure().unwrap();
        std::fs::remove_dir(base(&data).join("users")).unwrap();
        symlink(base(&real).join("users"), base(&data).join("users")).unwrap();
        assert!(data.ensure().is_err(), "symlinked users/ accepted");
    }

    // running ensure on every start must not fail once the folders exist
    #[test]
    fn ensure_is_repeatable() {
        let dir = tempfile::tempdir().unwrap();
        let data = DataDir::at(dir.path().join("securevault"));

        data.ensure().unwrap();
        data.ensure().unwrap();
    }
}
