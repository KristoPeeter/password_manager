// each record operation in one place: load, act, save, log. the ui only prompts and prints, so no menu path can skip the logging or the validation

use std::fmt;

use zeroize::Zeroizing;

use crate::audit::{Event, LogCheck, Logger, UnlockFailure};
use crate::paths::{DataDir, Username};
use crate::ui::clipboard::{ClipboardBackend, ClipboardManager};
use crate::vault::auth::{self, LoginError};
use crate::vault::crypto::KdfParams;
use crate::vault::lockout::LockState;
use crate::vault::models::{Credential, Vault, VaultError};
use crate::vault::storage::{self, Session, StorageError};
use crate::vault::validation::{self, Field};

#[derive(Debug)]
pub enum OpError {
    Vault(VaultError),
    Storage(StorageError),
    ClipboardUnavailable,
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpError::Vault(e) => write!(f, "{e}"),
            OpError::Storage(e) => write!(f, "{e}"),
            OpError::ClipboardUnavailable => write!(f, "Clipboard unavailable"),
        }
    }
}

impl From<VaultError> for OpError {
    fn from(e: VaultError) -> Self {
        OpError::Vault(e)
    }
}

impl From<StorageError> for OpError {
    fn from(e: StorageError) -> Self {
        OpError::Storage(e)
    }
}

// what list shows: there is no password field, so listing can't put one on screen
#[derive(Debug, PartialEq)]
pub struct Listed {
    pub service: String,
    pub username: String,
}

// a session plus what the log check at login found, for the ui to report
pub struct LoggedIn {
    pub session: Session,
    pub check: LogCheck,
}

pub fn create_user(
    dir: &DataDir,
    log: &Logger,
    user: &Username,
    password: &str,
) -> Result<LoggedIn, StorageError> {
    create_user_with_params(dir, log, user, password, KdfParams::DEFAULT)
}

// the tests use cheap kdf parameters, as in storage
pub(crate) fn create_user_with_params(
    dir: &DataDir,
    log: &Logger,
    user: &Username,
    password: &str,
    params: KdfParams,
) -> Result<LoggedIn, StorageError> {
    let session = match storage::create_user_with_params(dir, user, password, params) {
        Ok(session) => session,
        Err(e) => {
            // the user doesn't exist, so the log gets no name
            log_storage_failure(log, None, &e);
            return Err(e);
        }
    };
    let check = start_log_session(log, &session)?;
    log.log(Some(user), Event::UserCreated);
    Ok(LoggedIn { session, check })
}

pub fn login(
    dir: &DataDir,
    log: &Logger,
    user: &Username,
    password: &str,
    now: u64,
) -> Result<LoggedIn, LoginError> {
    let session = match auth::login(dir, user, password, now) {
        Ok(session) => session,
        Err(error) => {
            log_login_failure(log, user, &error);
            return Err(error);
        }
    };
    let check = start_log_session(log, &session).map_err(LoginError::Storage)?;
    // logged after the check, so this line is the first one the new seal covers
    log.log(Some(user), Event::UnlockSucceeded);
    Ok(LoggedIn { session, check })
}

// asked before the password prompt, so a locked user isn't asked for a password that can't be
// checked. a refusal is logged; an unknown user is never locked, so this reveals nothing
pub fn lock_state(dir: &DataDir, log: &Logger, user: &Username, now: u64) -> LockState {
    let state = auth::lock_state(dir, user, now);
    if let LockState::Locked { remaining_secs } = state {
        log.log(Some(user), Event::UnlockRefusedLocked { remaining_secs });
    }
    state
}

// the only way a session should end: the seal stops following the log, so events after this (someone else's failed logins included) count as "since your last session" next time. dropping the session then releases the vault lock
pub fn logout(log: &Logger, logged_in: LoggedIn) {
    log.end_session();
    drop(logged_in);
}

// checks the log against the user's seal and starts sealing. the first time, the vault is marked, so a deleted seal can't pass for a first login later
fn start_log_session(log: &Logger, session: &Session) -> Result<LogCheck, StorageError> {
    let mut vault = load_logged(log, session)?;
    let check = log.begin_session(session, vault.log_sealed());
    if !vault.log_sealed() {
        vault.mark_log_sealed();
        if let Err(e) = storage::save(session, &vault) {
            log_storage_failure(log, Some(session.user()), &e);
            return Err(e);
        }
    }
    Ok(check)
}

fn load_logged(log: &Logger, session: &Session) -> Result<Vault, StorageError> {
    storage::load(session).inspect_err(|e| log_storage_failure(log, Some(session.user()), e))
}

// unknown users are logged without a name: the typed name could be a mistyped password
fn log_login_failure(log: &Logger, user: &Username, error: &LoginError) {
    match error {
        LoginError::Locked { remaining_secs } => log.log(
            Some(user),
            Event::UnlockRefusedLocked {
                remaining_secs: *remaining_secs,
            },
        ),
        LoginError::BadCredentials {
            known_user: false, ..
        } => log.log(None, Event::UnlockFailed(UnlockFailure::UnknownUser)),
        LoginError::BadCredentials {
            known_user: true,
            failure,
        } => {
            // no count when the attempts file couldn't be written
            let failures = failure.as_ref().map_or(0, |f| f.failures);
            log.log(
                Some(user),
                Event::UnlockFailed(UnlockFailure::BadCredentials { failures }),
            );
            if let Some(locked_secs) = failure.as_ref().and_then(|f| f.locked_secs) {
                log.log(Some(user), Event::LockoutStarted { locked_secs });
            }
        }
        LoginError::Storage(StorageError::AlreadyOpen) => {
            log.log(Some(user), Event::SessionAlreadyOpen);
        }
        LoginError::Storage(e) => log_storage_failure(log, Some(user), e),
    }
}

pub fn list(session: &Session, log: &Logger) -> Result<Vec<Listed>, OpError> {
    let result = storage::load(session).map_err(OpError::from).map(|vault| {
        vault
            .credentials()
            .iter()
            .map(|c| Listed {
                service: c.service.clone(),
                username: c.username.clone(),
            })
            .collect()
    });
    finish(session, log, result, Event::CredentialsListed)
}

// asked right after the service prompt, so a bad or taken name is reported before the password is
// typed. returns the name as it will be stored (trimmed). a rejected name is logged like any other
pub fn check_new_service(
    session: &Session,
    log: &Logger,
    service: &str,
) -> Result<String, OpError> {
    let result = (|| {
        let service = validation::service(service).map_err(VaultError::from)?;
        let vault = storage::load(session)?;
        if vault.get(&service).is_some() {
            return Err(OpError::Vault(VaultError::DuplicateService));
        }
        Ok(service)
    })();
    if let Err(error) = &result
        && let Some(event) = failure_event(error)
    {
        log.log(Some(session.user()), event);
    }
    result
}

pub fn add(
    session: &Session,
    log: &Logger,
    service: &str,
    username: &str,
    mut password: Zeroizing<String>,
) -> Result<(), OpError> {
    let result = modify(session, |vault| {
        vault.add(Credential {
            service: service.to_string(),
            username: username.to_string(),
            // moved, not copied; the credential wipes it when the vault is dropped
            password: std::mem::take(&mut *password),
        })
    });
    finish(session, log, result, Event::CredentialAdded)
}

pub fn update_username(
    session: &Session,
    log: &Logger,
    service: &str,
    new: &str,
) -> Result<(), OpError> {
    let result = modify(session, |vault| vault.update_username(service, new));
    let event = Event::CredentialUpdated {
        field: Field::Username,
    };
    finish(session, log, result, event)
}

pub fn update_password(
    session: &Session,
    log: &Logger,
    service: &str,
    new: Zeroizing<String>,
) -> Result<(), OpError> {
    let result = modify(session, |vault| vault.update_password(service, new));
    let event = Event::CredentialUpdated {
        field: Field::Password,
    };
    finish(session, log, result, event)
}

pub fn delete(session: &Session, log: &Logger, service: &str) -> Result<(), OpError> {
    let result = modify(session, |vault| vault.remove(service));
    finish(session, log, result, Event::CredentialDeleted)
}

pub fn copy_password<B: ClipboardBackend>(
    session: &Session,
    log: &Logger,
    clipboard: Option<&ClipboardManager<B>>,
    service: &str,
) -> Result<(), OpError> {
    let result = (|| {
        let vault = storage::load(session)?;
        let credential = vault.get(service).ok_or(VaultError::NotFound)?;
        // never printed instead: without a clipboard the copy simply fails
        let clipboard = clipboard.ok_or(OpError::ClipboardUnavailable)?;
        clipboard
            .copy(&credential.password)
            .map_err(|_| OpError::ClipboardUnavailable)
    })();
    finish(session, log, result, Event::PasswordCopied)
}

fn modify(
    session: &Session,
    act: impl FnOnce(&mut Vault) -> Result<(), VaultError>,
) -> Result<(), OpError> {
    let mut vault = storage::load(session)?;
    act(&mut vault)?;
    storage::save(session, &vault)?;
    Ok(())
}

// success logs the operation's event; a failure logs at most one event saying what went wrong
fn finish<T>(
    session: &Session,
    log: &Logger,
    result: Result<T, OpError>,
    success: Event,
) -> Result<T, OpError> {
    let user = Some(session.user());
    match &result {
        Ok(_) => log.log(user, success),
        Err(error) => {
            if let Some(event) = failure_event(error) {
                log.log(user, event);
            }
        }
    }
    result
}

// a missing or duplicate service, or a vault too big to save, is an ordinary mistake: no event
fn failure_event(error: &OpError) -> Option<Event> {
    match error {
        OpError::Storage(e) => storage_event(e),
        OpError::Vault(VaultError::Invalid(v)) => {
            Some(Event::ValidationRejected { field: v.field })
        }
        OpError::Vault(_) => None,
        OpError::ClipboardUnavailable => Some(Event::ClipboardUnavailable),
    }
}

fn storage_event(error: &StorageError) -> Option<Event> {
    match error {
        StorageError::AccessDenied(check) => Some(Event::AccessDenied { check: *check }),
        StorageError::Unlock => Some(Event::IntegrityCheckFailed),
        // the kind only: an io error's own message can contain a path
        StorageError::Io(e) => Some(Event::IoError { kind: e.kind() }),
        _ => None,
    }
}

fn log_storage_failure(log: &Logger, user: Option<&Username>, error: &StorageError) {
    if let Some(event) = storage_event(error) {
        log.log(user, event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::UserFile;
    use crate::ui::clipboard::ClipboardError;
    use crate::vault::access::AccessCheck;
    use crate::vault::crypto::KdfParams;
    use crate::vault::storage::{self, create_user_with_params as storage_create};
    use crate::vault::validation::Field;
    use serde_json::Value;
    use std::fs;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const TS: u64 = 1_794_650_000;
    const NOW: u64 = 1_700_000_000;
    const PW: &str = "correct horse battery";

    fn clock() -> u64 {
        TS
    }

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

    // alice logged in, and a logger, as the menu has them
    fn alice(data: &DataDir) -> (Session, Logger) {
        let session = storage_create(data, &user("alice"), PW, KdfParams::TEST).unwrap();
        (session, Logger::open(data, clock))
    }

    fn secret(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_string())
    }

    fn events(data: &DataDir) -> Vec<Value> {
        match fs::read_to_string(data.log_file()) {
            Ok(text) => text
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn names(data: &DataDir) -> Vec<String> {
        events(data)
            .iter()
            .map(|e| e["event"].as_str().unwrap().to_string())
            .collect()
    }

    fn last_event(data: &DataDir) -> Value {
        events(data).pop().unwrap()
    }

    fn set_mode(path: &Path, mode: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    // fake clipboard so tests never touch the real one
    #[derive(Clone, Default)]
    struct Fake {
        content: Arc<Mutex<Option<String>>>,
        fail: bool,
    }

    impl ClipboardBackend for Fake {
        fn set_text(&mut self, text: &str) -> Result<(), ClipboardError> {
            if self.fail {
                return Err(ClipboardError);
            }
            *self.content.lock().unwrap() = Some(text.to_string());
            Ok(())
        }

        fn get_text(&mut self) -> Result<String, ClipboardError> {
            self.content.lock().unwrap().clone().ok_or(ClipboardError)
        }

        fn clear(&mut self) -> Result<(), ClipboardError> {
            *self.content.lock().unwrap() = None;
            Ok(())
        }
    }

    // long enough that the clear timer never fires during a test
    fn clipboard(fake: &Fake) -> ClipboardManager<Fake> {
        ClipboardManager::new(fake.clone(), Duration::from_secs(600))
    }

    fn add_github(session: &Session, log: &Logger) {
        add(session, log, "github", "alice-gh", secret("hunter2")).unwrap();
    }

    // --- record operations ---

    // every operation leaves exactly its own event, with the user it was done for
    #[test]
    fn each_operation_logs_its_event() {
        let (_dir, data) = data_dir();
        let (session, log) = alice(&data);
        let fake = Fake::default();

        add_github(&session, &log);
        list(&session, &log).unwrap();
        update_username(&session, &log, "github", "alice2").unwrap();
        update_password(&session, &log, "github", secret("hunter3")).unwrap();
        copy_password(&session, &log, Some(&clipboard(&fake)), "github").unwrap();
        delete(&session, &log, "github").unwrap();

        assert_eq!(
            names(&data),
            [
                "credential_added",
                "credentials_listed",
                "credential_updated",
                "credential_updated",
                "password_copied",
                "credential_deleted",
            ]
        );
        let events = events(&data);
        assert_eq!(events[2]["field"], "username");
        assert_eq!(events[3]["field"], "password");
        assert!(events.iter().all(|e| e["user"] == "alice"));
        assert_eq!(*fake.content.lock().unwrap(), Some("hunter3".to_string()));
    }

    // the operations really change the vault on disk, and list shows service and username only
    #[test]
    fn operations_act_on_the_vault() {
        let (_dir, data) = data_dir();
        let (session, log) = alice(&data);
        add_github(&session, &log);
        add(&session, &log, "gitlab", "al", secret("pw-gitlab")).unwrap();

        update_username(&session, &log, "github", "alice2").unwrap();
        update_password(&session, &log, "github", secret("hunter3")).unwrap();
        delete(&session, &log, "gitlab").unwrap();

        assert_eq!(
            list(&session, &log).unwrap(),
            [Listed {
                service: "github".to_string(),
                username: "alice2".to_string(),
            }]
        );
        let vault = storage::load(&session).unwrap();
        assert_eq!(vault.get("github").unwrap().password, "hunter3");
        assert!(vault.get("gitlab").is_none());
    }

    // a rejected field is logged by name only, and nothing is saved
    #[test]
    fn invalid_input_is_rejected_and_logged() {
        let (_dir, data) = data_dir();
        let (session, log) = alice(&data);

        let result = add(&session, &log, "bad\x1bservice", "u", secret("p"));

        assert!(
            matches!(result, Err(OpError::Vault(VaultError::Invalid(ref e))) if e.field == Field::Service),
            "{result:?}"
        );
        let event = last_event(&data);
        assert_eq!(event["event"], "validation_rejected");
        assert_eq!(event["field"], "service");
        assert!(storage::load(&session).unwrap().is_empty());

        add_github(&session, &log);
        let result = update_password(&session, &log, "github", secret(""));
        assert!(matches!(
            result,
            Err(OpError::Vault(VaultError::Invalid(_)))
        ));
        assert_eq!(last_event(&data)["field"], "password");
        assert_eq!(
            storage::load(&session)
                .unwrap()
                .get("github")
                .unwrap()
                .password,
            "hunter2"
        );
    }

    // a missing or duplicate service is an ordinary mistake, not a security event
    #[test]
    fn missing_or_duplicate_service_logs_nothing() {
        let (_dir, data) = data_dir();
        let (session, log) = alice(&data);
        add_github(&session, &log);
        let before = names(&data);

        let duplicate = add(&session, &log, "github", "x", secret("y"));
        let missing = delete(&session, &log, "nope");
        let missing_update = update_username(&session, &log, "nope", "x");

        assert!(matches!(
            duplicate,
            Err(OpError::Vault(VaultError::DuplicateService))
        ));
        assert!(matches!(missing, Err(OpError::Vault(VaultError::NotFound))));
        assert!(matches!(
            missing_update,
            Err(OpError::Vault(VaultError::NotFound))
        ));
        assert_eq!(names(&data), before);
    }

    // a vault changed on disk during the session is refused and logged as an integrity failure
    #[test]
    fn tampered_vault_mid_session_is_logged() {
        let (_dir, data) = data_dir();
        let (session, log) = alice(&data);
        add_github(&session, &log);
        let path = data.user_file(&user("alice"), UserFile::Vault);
        let mut json: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut ciphertext: Vec<char> = json["ciphertext"].as_str().unwrap().chars().collect();
        ciphertext[10] = if ciphertext[10] == 'A' { 'B' } else { 'A' };
        json["ciphertext"] = ciphertext.into_iter().collect::<String>().into();
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();

        let result = list(&session, &log);

        assert!(
            matches!(result, Err(OpError::Storage(StorageError::Unlock))),
            "{result:?}"
        );
        assert_eq!(last_event(&data)["event"], "integrity_check_failed");
    }

    // permissions loosened during the session: refused, and the failed check is named
    #[cfg(unix)]
    #[test]
    fn loosened_permissions_mid_session_are_refused() {
        let (_dir, data) = data_dir();
        let (session, log) = alice(&data);
        set_mode(&data.user_file(&user("alice"), UserFile::Vault), 0o644);

        let result = add(&session, &log, "github", "u", secret("p"));

        assert!(
            matches!(
                result,
                Err(OpError::Storage(StorageError::AccessDenied(
                    AccessCheck::Mode
                )))
            ),
            "{result:?}"
        );
        let event = last_event(&data);
        assert_eq!(event["event"], "access_denied");
        assert_eq!(event["check"], "mode");
    }

    // a save that fails on disk is logged with the error's kind, never its text
    #[cfg(unix)]
    #[test]
    fn io_failure_logs_its_kind() {
        let (_dir, data) = data_dir();
        let (session, log) = alice(&data);
        let folder = data.user_dir(&user("alice"));
        set_mode(&folder, 0o500);

        let result = add(&session, &log, "github", "u", secret("p"));

        set_mode(&folder, 0o700); // so the temp dir can be cleaned up
        assert!(
            matches!(result, Err(OpError::Storage(StorageError::Io(_)))),
            "{result:?}"
        );
        let event = last_event(&data);
        assert_eq!(event["event"], "io_error");
        assert_eq!(event["kind"], "PermissionDenied");
    }

    // no clipboard, or one that refuses the text: reported, logged, and nothing printed instead
    #[test]
    fn copy_without_clipboard_is_reported() {
        let (_dir, data) = data_dir();
        let (session, log) = alice(&data);
        add_github(&session, &log);
        let broken = Fake {
            fail: true,
            ..Fake::default()
        };

        let none = copy_password::<Fake>(&session, &log, None, "github");
        let failed = copy_password(&session, &log, Some(&clipboard(&broken)), "github");

        assert!(matches!(none, Err(OpError::ClipboardUnavailable)));
        assert!(matches!(failed, Err(OpError::ClipboardUnavailable)));
        let names = names(&data);
        assert_eq!(&names[names.len() - 2..], ["clipboard_unavailable"; 2]);
    }

    // logging is best-effort: a log that stops accepting writes mid-session changes nothing
    // about the operation itself
    #[cfg(unix)]
    #[test]
    fn unwritable_log_does_not_fail_operations() {
        let (_dir, data) = data_dir();
        let (session, log) = alice(&data);
        log.log(None, crate::audit::Event::AppStart);
        set_mode(&data.log_file(), 0o400);

        let result = add(&session, &log, "github", "u", secret("p"));

        assert!(result.is_ok(), "{result:?}");
        assert!(storage::load(&session).unwrap().get("github").is_some());
    }

    // the clipboard error has its own fixed message; the others keep theirs
    #[test]
    fn op_errors_show_the_spec_messages() {
        assert_eq!(
            OpError::ClipboardUnavailable.to_string(),
            "Clipboard unavailable"
        );
        assert_eq!(
            OpError::Storage(StorageError::Unlock).to_string(),
            "Couldn't unlock vault"
        );
        assert_eq!(
            OpError::Vault(VaultError::NotFound).to_string(),
            "Credential not found"
        );
    }

    // --- creating users and logging in ---

    fn create(data: &DataDir, log: &Logger, name: &str, password: &str) -> LoggedIn {
        create_user_with_params(data, log, &user(name), password, KdfParams::TEST).unwrap()
    }

    // Session has no Debug, so unwrap_err can't be used
    fn login_error(
        data: &DataDir,
        log: &Logger,
        name: &str,
        password: &str,
        now: u64,
    ) -> LoginError {
        match login(data, log, &user(name), password, now) {
            Ok(_) => panic!("{name} logged in"),
            Err(e) => e,
        }
    }

    // a new user is logged, sealed from the start, and the vault remembers it
    #[test]
    fn create_user_logs_and_seals() {
        let (_dir, data) = data_dir();
        let log = Logger::open(&data, clock);

        let created = create(&data, &log, "alice", PW);

        assert_eq!(
            created.check,
            LogCheck::Clean {
                failed_attempts_since_last_session: 0
            }
        );
        assert_eq!(names(&data), ["user_created"]);
        assert_eq!(last_event(&data)["user"], "alice");
        assert!(data.user_file(&user("alice"), UserFile::Seal).exists());
        assert!(storage::load(&created.session).unwrap().log_sealed());
    }

    // every way a login can end is logged: who, what, and the counts the spec asks for
    #[test]
    fn login_logs_each_outcome() {
        let (_dir, data) = data_dir();
        let log = Logger::open(&data, clock);
        logout(&log, create(&data, &log, "alice", PW));

        login_error(&data, &log, "alice", "wrong one", NOW);
        login_error(&data, &log, "nobody", PW, NOW);
        login_error(&data, &log, "alice", "wrong two", NOW);
        login_error(&data, &log, "alice", "wrong three", NOW);
        login_error(&data, &log, "alice", PW, NOW + 1);
        let logged_in = login(&data, &log, &user("alice"), PW, NOW + 30).unwrap();

        let events = events(&data);
        let summary: Vec<_> = events
            .iter()
            .map(|e| {
                (
                    e["event"].as_str().unwrap(),
                    e["user"].as_str(),
                    e.get("reason").and_then(Value::as_str),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("user_created", Some("alice"), None),
                ("unlock_failed", Some("alice"), Some("bad_credentials")),
                ("unlock_failed", None, Some("unknown_user")),
                ("unlock_failed", Some("alice"), Some("bad_credentials")),
                ("unlock_failed", Some("alice"), Some("bad_credentials")),
                ("lockout_started", Some("alice"), None),
                ("unlock_refused_locked", Some("alice"), None),
                ("unlock_succeeded", Some("alice"), None),
            ]
        );
        assert_eq!(events[4]["failures"], 3);
        assert_eq!(events[5]["locked_secs"], 30);
        assert_eq!(events[6]["remaining_secs"], 29);
        // the three wrong passwords since her last session
        assert_eq!(
            logged_in.check,
            LogCheck::Clean {
                failed_attempts_since_last_session: 3
            }
        );
    }

    // a second session for the same user is refused and logged, not counted as a failure
    #[test]
    fn second_session_is_logged() {
        let (_dir, data) = data_dir();
        let log = Logger::open(&data, clock);
        let first = create(&data, &log, "alice", PW);

        let error = login_error(&data, &log, "alice", PW, NOW);

        assert!(
            matches!(error, LoginError::Storage(StorageError::AlreadyOpen)),
            "{error:?}"
        );
        assert_eq!(last_event(&data)["event"], "session_already_open");
        drop(first);
    }

    // --- the no-secrets guarantee ---

    // every flow, including the failures, with recognisable values: none of them may appear in
    // the log or the seal, and neither may the vault key
    #[test]
    fn no_secret_ever_reaches_the_log() {
        const MASTER: &str = "MARK-master-correct-horse";
        const WRONG: &str = "MARK-wrongpw-battery";
        const STORED: &str = "MARK-stored-hunter2";
        const STORED_2: &str = "MARK-stored-hunter3";
        const SERVICE: &str = "MARK-service";
        const CUSER: &str = "MARK-cuser";
        const CUSER_2: &str = "MARK-cuser-two";
        const UNKNOWN: &str = "markunknown";
        let (_dir, data) = data_dir();
        let log = Logger::open(&data, clock);
        let fake = Fake::default();

        logout(&log, create(&data, &log, "alice", MASTER));
        login_error(&data, &log, "alice", WRONG, NOW);
        login_error(&data, &log, UNKNOWN, MASTER, NOW);
        login_error(&data, &log, UNKNOWN, WRONG, NOW);
        login_error(&data, &log, "alice", WRONG, NOW);
        login_error(&data, &log, "alice", WRONG, NOW); // locks
        login_error(&data, &log, "alice", MASTER, NOW + 1); // refused while locked
        let LoggedIn { session, .. } =
            login(&data, &log, &user("alice"), MASTER, NOW + 30).unwrap();

        add(&session, &log, SERVICE, CUSER, secret(STORED)).unwrap();
        list(&session, &log).unwrap();
        update_username(&session, &log, SERVICE, CUSER_2).unwrap();
        update_password(&session, &log, SERVICE, secret(STORED_2)).unwrap();
        copy_password(&session, &log, Some(&clipboard(&fake)), SERVICE).unwrap();
        copy_password::<Fake>(&session, &log, None, SERVICE).unwrap_err();
        add(
            &session,
            &log,
            &format!("{SERVICE}\x1b"),
            CUSER,
            secret(STORED),
        )
        .unwrap_err();
        add(&session, &log, SERVICE, CUSER, secret(STORED)).unwrap_err();
        update_password(&session, &log, "MARK-missing", secret(STORED)).unwrap_err();
        delete(&session, &log, SERVICE).unwrap();

        let mut text = fs::read_to_string(data.log_file()).unwrap();
        text.push_str(&fs::read_to_string(data.user_file(&user("alice"), UserFile::Seal)).unwrap());
        let key = hex::encode(session.key().as_slice());
        for marker in [
            MASTER, WRONG, STORED, STORED_2, SERVICE, CUSER, CUSER_2, UNKNOWN, "MARK", &key,
        ] {
            assert!(!text.contains(marker), "{marker:?} reached the log");
        }
        // the run really was logged, so the check above isn't vacuous
        assert!(names(&data).len() >= 15, "{:?}", names(&data));
    }

    // --- checks the ui makes before asking for a password ---

    // a locked user is told so before typing anything, and the refusal is logged once
    #[test]
    fn locked_user_is_reported_before_the_password_prompt() {
        let (_dir, data) = data_dir();
        let log = Logger::open(&data, clock);
        logout(&log, create(&data, &log, "alice", PW));
        assert_eq!(
            lock_state(&data, &log, &user("alice"), NOW),
            LockState::Open
        );
        assert_eq!(names(&data).len(), 1, "an open check logs nothing");
        for _ in 0..3 {
            login_error(&data, &log, "alice", "wrong", NOW);
        }

        let state = lock_state(&data, &log, &user("alice"), NOW + 10);

        assert_eq!(state, LockState::Locked { remaining_secs: 20 });
        let event = last_event(&data);
        assert_eq!(event["event"], "unlock_refused_locked");
        assert_eq!(event["remaining_secs"], 20);
        assert_eq!(
            lock_state(&data, &log, &user("nobody"), NOW),
            LockState::Open
        );
    }

    // a bad service name is rejected and logged before the password is typed; a taken one is
    // reported (unlogged, it's an ordinary mistake), comparing the trimmed name
    #[test]
    fn new_service_is_checked_before_the_password_prompt() {
        let (_dir, data) = data_dir();
        let (session, log) = alice(&data);
        add_github(&session, &log);

        let bad = check_new_service(&session, &log, "bad\x1bname");
        assert!(matches!(bad, Err(OpError::Vault(VaultError::Invalid(_)))));
        assert_eq!(last_event(&data)["event"], "validation_rejected");
        let logged = names(&data).len();

        let taken = check_new_service(&session, &log, "  github ");
        assert!(matches!(
            taken,
            Err(OpError::Vault(VaultError::DuplicateService))
        ));
        assert_eq!(names(&data).len(), logged);

        assert_eq!(
            check_new_service(&session, &log, " gitlab ").unwrap(),
            "gitlab"
        );
    }
}
