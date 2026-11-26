use std::{fs, path::Path};

use super::lockout::{self, Failure, LockState};
use super::storage::{self, Session, StorageError};
use crate::paths::{DataDir, UserFile, Username};

// argon2 takes any length
const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Debug)]
pub enum LoginError {
    Locked {
        remaining_secs: u64,
    },
    // failure is None for an unknown user: there is no attempts file to count in
    BadCredentials {
        known_user: bool,
        failure: Option<Failure>,
    },
    // access denied, already open, io: none of these count as a wrong password
    Storage(StorageError),
}

// Open for an unknown user, so the lock state never reveals who exists
pub fn lock_state(dir: &DataDir, user: &Username, now: u64) -> LockState {
    if !has_folder(dir, user) {
        return LockState::Open;
    }
    lockout::state(&dir.user_file(user, UserFile::Attempts), now)
}

pub fn login(
    dir: &DataDir,
    user: &Username,
    password: &str,
    now: u64,
) -> Result<Session, LoginError> {
    let attempts = dir.user_file(user, UserFile::Attempts);
    // the folder ( not the vault ) decides: a lock must hold even if the vault went missing.
    // a folder without a vault still ends up as an unknown user, through unlock's NotFound
    let known_user = has_folder(dir, user);

    // locked out
    if known_user && let LockState::Locked { remaining_secs } = lockout::state(&attempts, now) {
        return Err(LoginError::Locked { remaining_secs });
    }

    // Too long
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(wrong_password(known_user, &attempts, now));
    }

    match storage::unlock(dir, user, password) {
        Ok(session) => {
            let _ = lockout::clear(&attempts);
            Ok(session)
        }
        Err(StorageError::NotFound) => {
            // the same argon2 work as a real attempt so return time tells nothing about if credentials are actullay there or no
            storage::dummy_unlock(password);
            Err(LoginError::BadCredentials {
                known_user: false,
                failure: None,
            })
        }
        Err(StorageError::Unlock) => Err(wrong_password(true, &attempts, now)),
        Err(e) => Err(LoginError::Storage(e)),
    }
}

fn has_folder(dir: &DataDir, user: &Username) -> bool {
    fs::symlink_metadata(dir.user_dir(user)).is_ok()
}

// only a real user has an attempts file
fn wrong_password(known_user: bool, attempts: &Path, now: u64) -> LoginError {
    LoginError::BadCredentials {
        known_user,
        failure: if known_user {
            lockout::record_failure(attempts, now).ok()
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::UserFile;
    use crate::vault::crypto::KdfParams;
    use crate::vault::storage::{self, create_user_with_params};
    use std::fs;
    use std::path::{Path, PathBuf};

    const PW: &str = "correct horse battery";
    const WRONG: &str = "wrong horse battery";
    const NOW: u64 = 1_700_000_000;
    const MAX_PASSWORD_BYTES: usize = 1024;

    // a fresh data folder per test; the TempDir must stay alive as long as the DataDir is used
    fn data_dir() -> (tempfile::TempDir, DataDir) {
        let dir = tempfile::tempdir().unwrap();
        let data = DataDir::at(dir.path().join("securevault"));
        data.ensure().unwrap();
        (dir, data)
    }

    fn user(name: &str) -> Username {
        Username::parse(name).unwrap()
    }

    // creates the user and closes the session, as if they had logged out
    fn existing_user(data: &DataDir, name: &str, password: &str) {
        drop(create_user_with_params(data, &user(name), password, KdfParams::TEST).unwrap());
    }

    fn attempts_path(data: &DataDir, name: &str) -> PathBuf {
        data.user_file(&user(name), UserFile::Attempts)
    }

    // Session has no Debug, so unwrap_err can't be used
    fn login_error(data: &DataDir, name: &str, password: &str, now: u64) -> LoginError {
        match login(data, &user(name), password, now) {
            Ok(_) => panic!("{name} logged in"),
            Err(e) => e,
        }
    }

    fn failure_count(error: &LoginError) -> Option<u32> {
        match error {
            LoginError::BadCredentials {
                failure: Some(f), ..
            } => Some(f.failures),
            _ => None,
        }
    }

    // every file under the data folder, so a test can show nothing was created anywhere
    fn all_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.extend(all_files(&path));
            } else {
                files.push(path);
            }
        }
        files.sort();
        files
    }

    // --- known user ---

    // two typos, then the right password: logged in, and the slate is wiped
    #[test]
    fn right_password_logs_in_and_clears_failures() {
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);
        login_error(&data, "alice", WRONG, NOW);
        login_error(&data, "alice", WRONG, NOW);
        assert!(attempts_path(&data, "alice").exists());

        let session = login(&data, &user("alice"), PW, NOW).unwrap();

        assert_eq!(session.user(), &user("alice"));
        assert!(!attempts_path(&data, "alice").exists());
    }

    // each wrong password counts, and the third starts the lock
    #[test]
    fn wrong_password_counts() {
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);

        for expected in 1..=3 {
            let error = login_error(&data, "alice", WRONG, NOW);
            assert_eq!(failure_count(&error), Some(expected));
            let LoginError::BadCredentials {
                known_user,
                failure: Some(failure),
            } = error
            else {
                panic!("{error:?}");
            };
            assert!(known_user);
            let locked = (expected == 3).then_some(30);
            assert_eq!(failure.locked_secs, locked, "failure {expected}");
        }
        assert_eq!(
            lock_state(&data, &user("alice"), NOW),
            LockState::Locked { remaining_secs: 30 }
        );
    }

    // while locked, not even the right password gets in, and refused attempts don't add to
    // the count: nothing is tried, so nothing is learned
    #[test]
    fn locked_user_is_refused_even_with_the_right_password() {
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);
        for _ in 0..3 {
            login_error(&data, "alice", WRONG, NOW);
        }
        let before = fs::read(attempts_path(&data, "alice")).unwrap();

        for password in [PW, WRONG] {
            let error = login_error(&data, "alice", password, NOW + 10);
            assert!(
                matches!(error, LoginError::Locked { remaining_secs: 20 }),
                "{error:?}"
            );
        }
        assert_eq!(fs::read(attempts_path(&data, "alice")).unwrap(), before);
    }

    // a locked login is refused before the vault is touched, so it costs no argon2 work:
    // with the vault gone, reaching unlock would give a different error
    #[test]
    fn locked_user_is_refused_before_the_vault_is_read() {
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);
        for _ in 0..3 {
            login_error(&data, "alice", WRONG, NOW);
        }
        fs::remove_file(data.user_file(&user("alice"), UserFile::Vault)).unwrap();

        let error = login_error(&data, "alice", PW, NOW);

        assert!(matches!(error, LoginError::Locked { .. }), "{error:?}");
    }

    // the lock ends on time
    #[test]
    fn lock_expires() {
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);
        for _ in 0..3 {
            login_error(&data, "alice", WRONG, NOW);
        }

        assert!(login(&data, &user("alice"), PW, NOW + 30).is_ok());
    }

    // a damaged attempts file means the maximum lock, even with the right password
    #[test]
    fn damaged_attempts_file_locks_out() {
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);
        fs::write(attempts_path(&data, "alice"), b"garbage").unwrap();

        let error = login_error(&data, "alice", PW, NOW);

        assert!(
            matches!(
                error,
                LoginError::Locked {
                    remaining_secs: 900
                }
            ),
            "{error:?}"
        );
    }

    // --- unknown user ---

    // a missing user gets the same answer as a wrong password, and leaves no trace on disk
    #[test]
    fn unknown_user_looks_like_a_wrong_password() {
        let (dir, data) = data_dir();
        let before = all_files(dir.path());

        let error = login_error(&data, "nobody", PW, NOW);

        assert!(
            matches!(
                error,
                LoginError::BadCredentials {
                    known_user: false,
                    failure: None
                }
            ),
            "{error:?}"
        );
        assert!(!data.user_dir(&user("nobody")).exists());
        assert_eq!(all_files(dir.path()), before);
    }

    // a lock would confirm that the user exists, so unknown users never get one.
    // four attempts: one past the point where a real user would be locked
    #[test]
    fn unknown_user_is_never_locked() {
        let (_dir, data) = data_dir();

        for _ in 0..4 {
            let error = login_error(&data, "nobody", WRONG, NOW);
            assert!(
                matches!(error, LoginError::BadCredentials { failure: None, .. }),
                "{error:?}"
            );
        }
        assert_eq!(lock_state(&data, &user("nobody"), NOW), LockState::Open);
    }

    // the folder a crash during create leaves behind is not a user yet
    #[test]
    fn half_created_user_is_unknown() {
        let (_dir, data) = data_dir();
        let folder = data.user_dir(&user("alice"));
        fs::create_dir(&folder).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let error = login_error(&data, "alice", PW, NOW);

        assert!(
            matches!(
                error,
                LoginError::BadCredentials {
                    known_user: false,
                    failure: None
                }
            ),
            "{error:?}"
        );
        assert!(!attempts_path(&data, "alice").exists());
    }

    // --- password length ---

    // over the cap is refused without argon2, and still counts against a real user
    #[test]
    fn oversized_password_is_refused() {
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);
        let oversized = "a".repeat(MAX_PASSWORD_BYTES + 1);

        let known = login_error(&data, "alice", &oversized, NOW);
        let unknown = login_error(&data, "nobody", &oversized, NOW);

        assert_eq!(failure_count(&known), Some(1), "{known:?}");
        assert!(
            matches!(
                unknown,
                LoginError::BadCredentials {
                    known_user: false,
                    failure: None
                }
            ),
            "{unknown:?}"
        );
    }

    // the cap is in bytes and the limit itself is allowed
    #[test]
    fn password_of_exactly_the_cap_is_accepted() {
        let (_dir, data) = data_dir();
        let longest = "ä".repeat(MAX_PASSWORD_BYTES / 2); // 2 bytes each
        assert_eq!(longest.len(), MAX_PASSWORD_BYTES);
        existing_user(&data, "alice", &longest);

        assert!(login(&data, &user("alice"), &longest, NOW).is_ok());
    }

    // --- not a wrong password ---

    // a permissions problem is the system's fault, not a guess: it must not lock the user out
    #[cfg(unix)]
    #[test]
    fn access_denied_does_not_count_as_a_failure() {
        use crate::vault::access::AccessCheck;
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);
        let vault = data.user_file(&user("alice"), UserFile::Vault);
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o644)).unwrap();

        let error = login_error(&data, "alice", PW, NOW);

        assert!(
            matches!(
                error,
                LoginError::Storage(StorageError::AccessDenied(AccessCheck::Mode))
            ),
            "{error:?}"
        );
        assert!(!attempts_path(&data, "alice").exists());
    }

    // the right password while another session is open is refused, but not counted
    #[test]
    fn already_open_does_not_count_as_a_failure() {
        let (_dir, data) = data_dir();
        let first = create_user_with_params(&data, &user("alice"), PW, KdfParams::TEST).unwrap();

        let error = login_error(&data, "alice", PW, NOW);

        assert!(
            matches!(error, LoginError::Storage(StorageError::AlreadyOpen)),
            "{error:?}"
        );
        assert!(!attempts_path(&data, "alice").exists());
        drop(first);
        assert!(login(&data, &user("alice"), PW, NOW).is_ok());
    }

    // the session login returns is a real one: it loads the user's vault
    #[test]
    fn session_from_login_loads_the_vault() {
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);

        let session = login(&data, &user("alice"), PW, NOW).unwrap();

        assert!(storage::load(&session).unwrap().is_empty());
    }

    fn private_folder(path: &Path) {
        fs::create_dir(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    // a folder without a vault is not a user yet, so not even an oversized password starts a count there: a count left behind would lock out whoever creates the name later
    #[test]
    fn oversized_password_for_half_created_user_is_not_counted() {
        let (_dir, data) = data_dir();
        private_folder(&data.user_dir(&user("alice")));
        let oversized = "a".repeat(MAX_PASSWORD_BYTES + 1);

        for _ in 0..3 {
            let error = login_error(&data, "alice", &oversized, NOW);
            assert!(
                matches!(
                    error,
                    LoginError::BadCredentials {
                        known_user: false,
                        failure: None
                    }
                ),
                "{error:?}"
            );
        }
        assert!(!attempts_path(&data, "alice").exists());
    }

    // a user folder that links somewhere else is refused before attempts.json is read or written, so the link can't be used to create or overwrite a file outside the data folder
    #[cfg(unix)]
    #[test]
    fn symlinked_user_folder_is_refused_before_attempts_are_touched() {
        use crate::vault::access::AccessCheck;
        use std::os::unix::fs::symlink;
        let (dir, data) = data_dir();
        let outside = dir.path().join("outside");
        private_folder(&outside);
        let planted = outside.join("attempts.json");
        fs::write(&planted, "DO_NOT_TOUCH").unwrap();
        symlink(&outside, data.user_dir(&user("bob"))).unwrap();
        let oversized = "a".repeat(MAX_PASSWORD_BYTES + 1);

        assert_eq!(lock_state(&data, &user("bob"), NOW), LockState::Open);
        for password in [WRONG, oversized.as_str()] {
            let error = login_error(&data, "bob", password, NOW);
            assert!(
                matches!(
                    error,
                    LoginError::Storage(StorageError::AccessDenied(AccessCheck::Symlink))
                ),
                "{error:?}"
            );
        }
        assert_eq!(fs::read_to_string(&planted).unwrap(), "DO_NOT_TOUCH");

        // nothing there to begin with: nothing gets created either
        fs::remove_file(&planted).unwrap();
        lock_state(&data, &user("bob"), NOW);
        login_error(&data, "bob", &oversized, NOW);
        assert!(!planted.exists());
    }

    // the oversized-password shortcut must not skip the checks unlock would have made
    #[cfg(unix)]
    #[test]
    fn loose_user_folder_is_refused_before_attempts_are_touched() {
        use crate::vault::access::AccessCheck;
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);
        let folder = data.user_dir(&user("alice"));
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o777)).unwrap();

        let error = login_error(&data, "alice", &"a".repeat(MAX_PASSWORD_BYTES + 1), NOW);

        assert!(
            matches!(
                error,
                LoginError::Storage(StorageError::AccessDenied(AccessCheck::Mode))
            ),
            "{error:?}"
        );
        assert!(!attempts_path(&data, "alice").exists());
    }

    // logins started at the same moment must not slip past the lockout: attempts for one user are taken one at a time, so exactly three wrong passwords are tried and the rest are refused
    #[test]
    fn parallel_wrong_passwords_still_lock_after_three() {
        const RACERS: usize = 8;
        let (_dir, data) = data_dir();
        existing_user(&data, "alice", PW);
        let start = std::sync::Barrier::new(RACERS);

        let errors: Vec<LoginError> = std::thread::scope(|s| {
            let racers: Vec<_> = (0..RACERS)
                .map(|_| {
                    s.spawn(|| {
                        start.wait();
                        login_error(&data, "alice", WRONG, NOW)
                    })
                })
                .collect();
            racers.into_iter().map(|r| r.join().unwrap()).collect()
        });

        let tried = errors
            .iter()
            .filter(|e| matches!(e, LoginError::BadCredentials { .. }))
            .count();
        let refused = errors
            .iter()
            .filter(|e| matches!(e, LoginError::Locked { .. }))
            .count();
        assert_eq!((tried, refused), (3, RACERS - 3), "{errors:?}");
        assert_eq!(
            lock_state(&data, &user("alice"), NOW),
            LockState::Locked { remaining_secs: 30 }
        );
    }
}
