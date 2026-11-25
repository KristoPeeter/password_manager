// the record operations (task 10) and the login screen (task 11) are the callers; until then
// only the tests use this module
#![allow(dead_code)]

use std::{io, path::PathBuf};

use crate::paths::{DataDir, Username};
use crate::vault::access::AccessCheck;
use crate::vault::validation::Field;

// unknown users have no attempts file, so only a wrong password for a real user has a count
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnlockFailure {
    BadCredentials { failures: u32 },
    UnknownUser,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TamperProblem {
    ChainBroken,
    SealMismatch,
    SealedEntryMissing,
}

// one variant per row of the spec's event table. every field is a number or a fixed name, never
// a string from input or a path: that is what keeps secrets out of the log
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Event {
    AppStart,
    AppExit { code: u8 },
    UserCreated,
    UnlockSucceeded,
    UnlockFailed(UnlockFailure),
    LockoutStarted { locked_secs: u64 },
    UnlockRefusedLocked { remaining_secs: u64 },
    SessionAlreadyOpen,
    CredentialsListed,
    CredentialAdded,
    CredentialUpdated { field: Field },
    CredentialDeleted,
    PasswordCopied,
    ClipboardUnavailable,
    IntegrityCheckFailed,
    AccessDenied { check: AccessCheck },
    ValidationRejected { field: Field },
    IoError { kind: io::ErrorKind },
    LogTamperDetected { problem: TamperProblem },
}

impl Event {
    pub fn name(&self) -> &'static str {
        todo!("task 8")
    }

    pub fn level(&self) -> &'static str {
        todo!("task 8")
    }
}

pub struct Logger {
    log: PathBuf,
    rotated: PathBuf,
    clock: fn() -> u64,
    max_bytes: u64,
    available: bool,
}

impl Logger {
    // never fails: a log that can't be used leaves the logger unavailable, and the app goes on
    pub fn open(dir: &DataDir, clock: fn() -> u64) -> Self {
        let _ = (dir, clock);
        todo!("task 8")
    }

    // the rotation size is a parameter only so the tests don't need to write a megabyte
    pub(crate) fn open_with_limit(dir: &DataDir, clock: fn() -> u64, max_bytes: u64) -> Self {
        let _ = (dir, clock, max_bytes);
        todo!("task 8")
    }

    pub fn is_available(&self) -> bool {
        todo!("task 8")
    }

    // best-effort: never panics, never returns an error
    pub fn log(&self, user: Option<&Username>, event: Event) {
        let _ = (user, event);
        todo!("task 8")
    }
}

pub(crate) struct Entry {
    pub seq: u64,
    pub hash: [u8; 32],
    pub user: Option<String>,
    pub event: String,
}

// events.log.1 then events.log, every seq and prev link checked
pub(crate) fn read_chain(dir: &DataDir) -> Result<Vec<Entry>, TamperProblem> {
    let _ = dir;
    todo!("task 8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::Path;

    const TS: u64 = 1_794_650_000;
    const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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

    fn lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn write_lines(path: &Path, lines: &[String]) {
        let mut text = lines.join("\n");
        text.push('\n');
        fs::write(path, text).unwrap();
    }

    fn sha_hex(line: &str) -> String {
        Sha256::digest(line.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn set_mode(path: &Path, mode: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    // every event name in the spec's table, so a variant missing from all_events is noticed
    const SPEC_NAMES: [&str; 19] = [
        "app_start",
        "app_exit",
        "user_created",
        "unlock_succeeded",
        "unlock_failed",
        "lockout_started",
        "unlock_refused_locked",
        "session_already_open",
        "credentials_listed",
        "credential_added",
        "credential_updated",
        "credential_deleted",
        "password_copied",
        "clipboard_unavailable",
        "integrity_check_failed",
        "access_denied",
        "validation_rejected",
        "io_error",
        "log_tamper_detected",
    ];

    fn all_events() -> Vec<Event> {
        vec![
            Event::AppStart,
            Event::AppExit { code: 1 },
            Event::UserCreated,
            Event::UnlockSucceeded,
            Event::UnlockFailed(UnlockFailure::BadCredentials { failures: 2 }),
            Event::UnlockFailed(UnlockFailure::UnknownUser),
            Event::LockoutStarted { locked_secs: 30 },
            Event::UnlockRefusedLocked { remaining_secs: 12 },
            Event::SessionAlreadyOpen,
            Event::CredentialsListed,
            Event::CredentialAdded,
            Event::CredentialUpdated {
                field: Field::Password,
            },
            Event::CredentialDeleted,
            Event::PasswordCopied,
            Event::ClipboardUnavailable,
            Event::IntegrityCheckFailed,
            Event::AccessDenied {
                check: AccessCheck::Mode,
            },
            Event::ValidationRejected {
                field: Field::Service,
            },
            Event::IoError {
                kind: io::ErrorKind::PermissionDenied,
            },
            Event::LogTamperDetected {
                problem: TamperProblem::SealMismatch,
            },
        ]
    }

    // the spec's event table, written out independently of the code under test. the match is
    // exhaustive, so a new variant can't compile until its documented shape is added here
    fn documented(event: &Event) -> (&'static str, &'static str, Value) {
        match *event {
            Event::AppStart => ("app_start", "info", json!({})),
            Event::AppExit { code } => ("app_exit", "info", json!({ "code": code })),
            Event::UserCreated => ("user_created", "info", json!({})),
            Event::UnlockSucceeded => ("unlock_succeeded", "info", json!({})),
            Event::UnlockFailed(UnlockFailure::BadCredentials { failures }) => (
                "unlock_failed",
                "warn",
                json!({ "reason": "bad_credentials", "failures": failures }),
            ),
            Event::UnlockFailed(UnlockFailure::UnknownUser) => {
                ("unlock_failed", "warn", json!({ "reason": "unknown_user" }))
            }
            Event::LockoutStarted { locked_secs } => (
                "lockout_started",
                "warn",
                json!({ "locked_secs": locked_secs }),
            ),
            Event::UnlockRefusedLocked { remaining_secs } => (
                "unlock_refused_locked",
                "warn",
                json!({ "remaining_secs": remaining_secs }),
            ),
            Event::SessionAlreadyOpen => ("session_already_open", "warn", json!({})),
            Event::CredentialsListed => ("credentials_listed", "info", json!({})),
            Event::CredentialAdded => ("credential_added", "info", json!({})),
            Event::CredentialUpdated { field } => (
                "credential_updated",
                "info",
                json!({ "field": field.as_str() }),
            ),
            Event::CredentialDeleted => ("credential_deleted", "info", json!({})),
            Event::PasswordCopied => ("password_copied", "info", json!({})),
            Event::ClipboardUnavailable => ("clipboard_unavailable", "warn", json!({})),
            Event::IntegrityCheckFailed => ("integrity_check_failed", "error", json!({})),
            Event::AccessDenied { check } => {
                ("access_denied", "error", json!({ "check": check.as_str() }))
            }
            Event::ValidationRejected { field } => (
                "validation_rejected",
                "info",
                json!({ "field": field.as_str() }),
            ),
            Event::IoError { kind } => {
                ("io_error", "error", json!({ "kind": format!("{kind:?}") }))
            }
            Event::LogTamperDetected { problem } => {
                let problem = match problem {
                    TamperProblem::ChainBroken => "chain_broken",
                    TamperProblem::SealMismatch => "seal_mismatch",
                    TamperProblem::SealedEntryMissing => "sealed_entry_missing",
                };
                (
                    "log_tamper_detected",
                    "error",
                    json!({ "problem": problem }),
                )
            }
        }
    }

    // --- line format ---

    // every event becomes one json line with the common fields, its name and level from the
    // table, and exactly its documented extra fields: nothing more can slip in
    #[test]
    fn each_event_serializes_to_the_documented_shape() {
        let names: std::collections::BTreeSet<_> =
            all_events().iter().map(|e| documented(e).0).collect();
        assert_eq!(names, SPEC_NAMES.into_iter().collect());

        for event in all_events() {
            let (_dir, data) = data_dir();
            let logger = Logger::open(&data, clock);
            logger.log(Some(&user("alice")), event);

            let line = lines(&data.log_file()).pop().unwrap();
            let json: Value = serde_json::from_str(&line).unwrap();
            let (name, level, extras) = documented(&event);

            assert_eq!(event.name(), name, "{event:?}");
            assert_eq!(event.level(), level, "{event:?}");
            let mut expected = json!({
                "seq": 1,
                "ts": TS,
                "level": level,
                "event": name,
                "user": "alice",
                "prev": ZEROS,
            });
            for (key, value) in extras.as_object().unwrap() {
                expected[key] = value.clone();
            }
            assert_eq!(json, expected, "{event:?}");
        }
    }

    // the documented field order, so a line reads the same way every time: the common fields,
    // then the extras, then the link to the previous line
    #[test]
    fn fields_are_in_the_documented_order() {
        let (_dir, data) = data_dir();
        let logger = Logger::open(&data, clock);
        logger.log(
            Some(&user("alice")),
            Event::AccessDenied {
                check: AccessCheck::Owner,
            },
        );

        let line = lines(&data.log_file()).pop().unwrap();
        let keys = ["seq", "ts", "level", "event", "user", "check", "prev"];
        let positions: Vec<usize> = keys
            .iter()
            .map(|k| line.find(&format!("\"{k}\":")).unwrap())
            .collect();
        assert!(positions.is_sorted(), "{line}");
    }

    // events before login, or for an unknown name, carry no user at all
    #[test]
    fn user_is_null_without_a_user() {
        let (_dir, data) = data_dir();
        let logger = Logger::open(&data, clock);

        logger.log(None, Event::AppStart);

        let line = lines(&data.log_file()).pop().unwrap();
        let json: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(json["user"], Value::Null);
    }

    // --- the chain ---

    // seq counts up from 1; the first prev is 64 zeros and each later one is the hash of the
    // line before; read_chain gives back the same entries
    #[test]
    fn seq_and_prev_chain_up() {
        let (_dir, data) = data_dir();
        let logger = Logger::open(&data, clock);
        logger.log(None, Event::AppStart);
        logger.log(Some(&user("alice")), Event::UnlockSucceeded);
        logger.log(Some(&user("alice")), Event::CredentialAdded);

        let text = fs::read_to_string(data.log_file()).unwrap();
        assert!(text.ends_with('\n'));
        let lines = lines(&data.log_file());
        assert_eq!(lines.len(), 3);
        let mut prev = ZEROS.to_string();
        for (i, line) in lines.iter().enumerate() {
            let json: Value = serde_json::from_str(line).unwrap();
            assert_eq!(json["seq"], i as u64 + 1);
            assert_eq!(json["prev"], prev.as_str(), "line {}", i + 1);
            prev = sha_hex(line);
        }

        let entries = read_chain(&data).unwrap_or_else(|p| panic!("{p:?}"));
        let summary: Vec<_> = entries
            .iter()
            .map(|e| (e.seq, e.user.as_deref(), e.event.as_str()))
            .collect();
        assert_eq!(
            summary,
            [
                (1, None, "app_start"),
                (2, Some("alice"), "unlock_succeeded"),
                (3, Some("alice"), "credential_added"),
            ]
        );
        for (entry, line) in entries.iter().zip(&lines) {
            assert_eq!(
                sha_hex(line),
                entry.hash.map(|b| format!("{b:02x}")).concat()
            );
        }
    }

    // a fresh install has no log yet, which is a valid, empty chain
    #[test]
    fn no_log_is_an_empty_chain() {
        let (_dir, data) = data_dir();

        assert!(
            read_chain(&data)
                .unwrap_or_else(|p| panic!("{p:?}"))
                .is_empty()
        );
    }

    // rotation moves the old file aside but the chain carries on through it: seq keeps
    // counting and the new file's first line links to the old file's last
    #[test]
    fn rotation_keeps_the_chain() {
        let (_dir, data) = data_dir();
        let logger = Logger::open_with_limit(&data, clock, 400);
        for _ in 0..20 {
            logger.log(Some(&user("alice")), Event::CredentialsListed);
        }

        assert!(data.rotated_log_file().exists());
        let old = lines(&data.rotated_log_file());
        let new = lines(&data.log_file());
        let first_new: Value = serde_json::from_str(&new[0]).unwrap();
        assert_eq!(first_new["prev"], sha_hex(old.last().unwrap()).as_str());

        let entries = read_chain(&data).unwrap_or_else(|p| panic!("{p:?}"));
        assert_eq!(entries.last().unwrap().seq, 20);
        for pair in entries.windows(2) {
            assert_eq!(pair[1].seq, pair[0].seq + 1);
        }
        // only two files are kept, so the oldest entries have rotated away
        assert!(entries.len() < 20);
    }

    // every kind of edit to a line other than the last breaks a link
    #[test]
    fn read_chain_detects_edits() {
        type Edit = fn(&mut Vec<String>);
        let edits: [(&str, Edit); 5] = [
            ("one byte changed", |l| {
                l[1] = l[1].replacen(&TS.to_string(), &(TS + 1).to_string(), 1);
            }),
            ("line deleted", |l| {
                l.remove(2);
            }),
            ("line inserted", |l| {
                let copy = l[1].clone();
                l.insert(2, copy);
            }),
            ("lines swapped", |l| l.swap(1, 2)),
            ("non-json line", |l| l.push("not json".to_string())),
        ];
        for (name, edit) in edits {
            let (_dir, data) = data_dir();
            let logger = Logger::open(&data, clock);
            for _ in 0..5 {
                logger.log(Some(&user("alice")), Event::CredentialAdded);
            }
            let mut lines = lines(&data.log_file());
            edit(&mut lines);
            write_lines(&data.log_file(), &lines);

            assert_eq!(
                read_chain(&data).err(),
                Some(TamperProblem::ChainBroken),
                "{name}"
            );
        }
    }

    // a crash mid-append leaves half a line: the check reports it, and the next event still
    // goes on a line of its own instead of being glued to the fragment
    #[test]
    fn partial_last_line_is_handled() {
        let (_dir, data) = data_dir();
        let logger = Logger::open(&data, clock);
        for _ in 0..3 {
            logger.log(Some(&user("alice")), Event::CredentialAdded);
        }
        let bytes = fs::read(data.log_file()).unwrap();
        fs::write(data.log_file(), &bytes[..bytes.len() - 10]).unwrap();

        assert_eq!(read_chain(&data).err(), Some(TamperProblem::ChainBroken));

        logger.log(None, Event::AppExit { code: 0 });
        let last = lines(&data.log_file()).pop().unwrap();
        let json: Value = serde_json::from_str(&last).unwrap();
        assert_eq!(json["event"], "app_exit");
    }

    // two app processes logging at once must not interleave lines or fork the chain
    #[test]
    fn two_writers_keep_one_chain() {
        let (_dir, data) = data_dir();
        let alice = Logger::open(&data, clock);
        let bob = Logger::open(&data, clock);

        std::thread::scope(|s| {
            for (logger, name) in [(&alice, "alice"), (&bob, "bob")] {
                s.spawn(move || {
                    for _ in 0..100 {
                        logger.log(Some(&user(name)), Event::CredentialAdded);
                    }
                });
            }
        });

        let entries = read_chain(&data).unwrap_or_else(|p| panic!("{p:?}"));
        assert_eq!(entries.len(), 200);
        assert_eq!(entries.last().unwrap().seq, 200);
    }

    // --- the file itself ---

    // the log says who logged in and when; other local users have no business reading it
    #[cfg(unix)]
    #[test]
    fn log_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = data_dir();
        let logger = Logger::open(&data, clock);
        logger.log(None, Event::AppStart);

        let mode = fs::metadata(data.log_file()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // logging is best-effort: a log that can't be created must not stop the app
    #[cfg(unix)]
    #[test]
    fn unwritable_log_is_silently_unavailable() {
        let (dir, data) = data_dir();
        let base = dir.path().join("securevault");
        set_mode(&base, 0o500);

        let logger = Logger::open(&data, clock);
        logger.log(None, Event::AppStart);

        let available = logger.is_available();
        let created = data.log_file().exists();
        set_mode(&base, 0o700); // so the temp dir can be cleaned up
        assert!(!available);
        assert!(!created);
    }

    // a log others can read gets the same treatment as a vault others can read: not used,
    // and not quietly fixed
    #[cfg(unix)]
    #[test]
    fn group_readable_log_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = data_dir();
        Logger::open(&data, clock).log(None, Event::AppStart);
        set_mode(&data.log_file(), 0o644);
        let before = fs::read(data.log_file()).unwrap();

        let logger = Logger::open(&data, clock);
        logger.log(None, Event::AppStart);

        assert!(!logger.is_available());
        assert_eq!(fs::read(data.log_file()).unwrap(), before);
        let mode = fs::metadata(data.log_file()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    // a symlink in place of the log could make the app append to any file the user can write
    #[cfg(unix)]
    #[test]
    fn symlinked_log_is_refused() {
        use std::os::unix::fs::symlink;
        let (dir, data) = data_dir();
        let target = dir.path().join("target");
        fs::write(&target, "keep me\n").unwrap();
        set_mode(&target, 0o600);
        symlink(&target, data.log_file()).unwrap();

        let logger = Logger::open(&data, clock);
        logger.log(None, Event::AppStart);

        assert!(!logger.is_available());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep me\n");
    }
}
