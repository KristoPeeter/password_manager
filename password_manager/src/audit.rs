use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};

use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::paths::{DataDir, UserFile, Username};
use crate::vault::access::{self, AccessCheck, AccessError};
use crate::vault::storage::{Session, write_atomically};
use crate::vault::validation::Field;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MAX_LOG_BYTES: u64 = 1024 * 1024;
// read_chain refuses anything this big: a real file is at most the limit plus one line
const MAX_READ_BYTES: u64 = 16 * MAX_LOG_BYTES;
// enough to hold the last few lines when looking up the previous seq and hash
const TAIL_BYTES: u64 = 64 * 1024;
// what the very first line links to
const GENESIS: [u8; 32] = [0; 32];
// a separate key for the seal, so the vault key itself is never used for anything else
const SEAL_CONTEXT: &[u8] = b"securevault log seal v1";
// a real seal is about 300 bytes
const MAX_SEAL_BYTES: u64 = 1024;
// an append holds the lock for well under a millisecond; anything longer is a stuck or hostile holder, and the event is dropped rather than hanging the app
const LOCK_WAIT: Duration = Duration::from_millis(500);
const LOCK_RETRY: Duration = Duration::from_millis(2);

type HmacSha256 = Hmac<Sha256>;

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

impl TamperProblem {
    pub fn as_str(self) -> &'static str {
        match self {
            TamperProblem::ChainBroken => "chain_broken",
            TamperProblem::SealMismatch => "seal_mismatch",
            TamperProblem::SealedEntryMissing => "sealed_entry_missing",
        }
    }
}

// one variant per row of the spec's event table. every field is a number or a fixed name, never a string from input or a path: that is what keeps secrets out of the log
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
        match self {
            Event::AppStart => "app_start",
            Event::AppExit { .. } => "app_exit",
            Event::UserCreated => "user_created",
            Event::UnlockSucceeded => "unlock_succeeded",
            Event::UnlockFailed(_) => "unlock_failed",
            Event::LockoutStarted { .. } => "lockout_started",
            Event::UnlockRefusedLocked { .. } => "unlock_refused_locked",
            Event::SessionAlreadyOpen => "session_already_open",
            Event::CredentialsListed => "credentials_listed",
            Event::CredentialAdded => "credential_added",
            Event::CredentialUpdated { .. } => "credential_updated",
            Event::CredentialDeleted => "credential_deleted",
            Event::PasswordCopied => "password_copied",
            Event::ClipboardUnavailable => "clipboard_unavailable",
            Event::IntegrityCheckFailed => "integrity_check_failed",
            Event::AccessDenied { .. } => "access_denied",
            Event::ValidationRejected { .. } => "validation_rejected",
            Event::IoError { .. } => "io_error",
            Event::LogTamperDetected { .. } => "log_tamper_detected",
        }
    }

    pub fn level(&self) -> &'static str {
        match self {
            Event::UnlockFailed(_)
            | Event::LockoutStarted { .. }
            | Event::UnlockRefusedLocked { .. }
            | Event::SessionAlreadyOpen
            | Event::ClipboardUnavailable => "warn",
            Event::IntegrityCheckFailed
            | Event::AccessDenied { .. }
            | Event::IoError { .. }
            | Event::LogTamperDetected { .. } => "error",
            _ => "info",
        }
    }

    fn extras(&self) -> Extras {
        let mut extras = Extras::default();
        match *self {
            Event::AppExit { code } => extras.code = Some(code),
            Event::UnlockFailed(UnlockFailure::BadCredentials { failures }) => {
                extras.reason = Some("bad_credentials");
                extras.failures = Some(failures);
            }
            Event::UnlockFailed(UnlockFailure::UnknownUser) => {
                extras.reason = Some("unknown_user");
            }
            Event::LockoutStarted { locked_secs } => extras.locked_secs = Some(locked_secs),
            Event::UnlockRefusedLocked { remaining_secs } => {
                extras.remaining_secs = Some(remaining_secs);
            }
            Event::CredentialUpdated { field } | Event::ValidationRejected { field } => {
                extras.field = Some(field.as_str());
            }
            Event::AccessDenied { check } => extras.check = Some(check.as_str()),
            // the kind's name only: an io error's own message can contain a path
            Event::IoError { kind } => extras.kind = Some(format!("{kind:?}")),
            Event::LogTamperDetected { problem } => extras.problem = Some(problem.as_str()),
            _ => {}
        }
        extras
    }
}

// the field order here is the order in the file
#[derive(Serialize)]
struct Line<'a> {
    seq: u64,
    ts: u64,
    level: &'static str,
    event: &'static str,
    user: Option<&'a str>,
    #[serde(flatten)]
    extras: Extras,
    prev: String,
}

#[derive(Default, Serialize)]
struct Extras {
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failures: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locked_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    check: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<&'static str>,
}

// what read_chain needs from a line; the extras are covered by the hash
#[derive(Deserialize)]
struct Stored {
    seq: u64,
    user: Option<String>,
    event: String,
    prev: String,
}

pub struct Logger {
    log: PathBuf,
    rotated: PathBuf,
    // appends are serialised on this file, not on events.log: rotation renames events.log, and a writer waiting on the old file would then append to events.log.1
    lock: PathBuf,
    clock: fn() -> u64,
    max_bytes: u64,
    available: bool,
    dir: DataDir,
    // Some while a user is logged in: every event then moves their seal to the newest line
    seal: Mutex<Option<ActiveSeal>>,
}

struct ActiveSeal {
    key: Zeroizing<[u8; 32]>,
    path: PathBuf,
    // set once the user was warned about a break: the line the check starts from instead of the first one, so the same break isn't reported again
    trusted_from: Option<LinePoint>,
}

//  nothing can be changed without the key
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealFile {
    seq: u64,
    hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from_hash: Option<String>,
    mac: String,
}

type LinePoint = (u64, [u8; 32]);

// a seal whose mac verified; nothing in it has been compared with the log yet
struct AuthenticSeal {
    seq: u64,
    hash: [u8; 32],
    trusted_from: Option<LinePoint>,
}

impl Logger {
    // never fails: a log that can't be used leaves the logger unavailable, and the app goes on
    pub fn open(dir: &DataDir, clock: fn() -> u64) -> Self {
        Self::open_with_limit(dir, clock, MAX_LOG_BYTES)
    }

    // the rotation size is a parameter only so the tests don't need to write a megabyte
    pub(crate) fn open_with_limit(dir: &DataDir, clock: fn() -> u64, max_bytes: u64) -> Self {
        let log = dir.log_file();
        let lock = log.with_extension("log.lock");
        let available = open_private(&log).is_ok() && access::check_file(&log).is_ok();
        Self {
            log,
            rotated: dir.rotated_log_file(),
            lock,
            clock,
            max_bytes,
            available,
            dir: dir.clone(),
            seal: Mutex::new(None),
        }
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    // best-effort: never panics, never returns an error
    pub fn log(&self, user: Option<&Username>, event: Event) {
        if !self.available {
            return;
        }
        if let Ok(written) = self.append(user, event)
            && let Some(seal) = self.active_seal().as_ref()
        {
            let _ = write_seal(seal, written);
        }
    }

    // a poisoned lock only means another thread panicked while holding it; the seal is still usable
    fn active_seal(&self) -> MutexGuard<'_, Option<ActiveSeal>> {
        self.seal.lock().unwrap_or_else(|e| e.into_inner())
    }

    // returns the seq and hash of the line it wrote, for the seal
    fn append(&self, user: Option<&Username>, event: Event) -> io::Result<(u64, [u8; 32])> {
        // held until the end of this call; the os releases it if the process dies
        let lock = open_private(&self.lock)?;
        wait_for_lock(&lock)?;

        // checked on every append, not only at open: the file may have been swapped since
        match access::check_file(&self.log) {
            Ok(()) => {}
            Err(AccessError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(io::Error::other("log refused")),
        }
        if fs::metadata(&self.log).is_ok_and(|m| m.len() > self.max_bytes) {
            fs::rename(&self.log, &self.rotated)?;
        }

        // the new line links to the last line of events.log, or after a rotation to the last line of events.log.1
        let (last, unterminated) = match tail(&self.log)? {
            Some(tail) => (Some(tail.last), !tail.terminated),
            None => (tail(&self.rotated)?.map(|t| t.last), false),
        };
        let (seq, prev) = last.unwrap_or((0, GENESIS));
        let line = serde_json::to_string(&Line {
            seq: seq + 1,
            ts: (self.clock)(),
            level: event.level(),
            event: event.name(),
            user: user.map(Username::as_str),
            extras: event.extras(),
            prev: hex::encode(prev),
        })
        .map_err(io::Error::other)?;

        let mut out = String::with_capacity(line.len() + 2);
        // after a crash mid-append, the new line must not be glued to the fragment
        if unterminated {
            out.push('\n');
        }
        out.push_str(&line);
        out.push('\n');
        let mut file = open_private(&self.log)?;
        file.write_all(out.as_bytes())?;
        drop(lock);
        Ok((seq + 1, sha256(line.as_bytes())))
    }
}

// what the log check at login found
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogCheck {
    Clean {
        failed_attempts_since_last_session: u32,
    },
    Tampered(TamperProblem),
}

impl Logger {
    // checks the log against this user's seal, then keeps the seal on the newest line for as long as the session lasts. vault_says_sealed comes from the vault, so deleting log.seal can't pass for a first login
    pub fn begin_session(&self, session: &Session, vault_says_sealed: bool) -> LogCheck {
        let user = session.user();
        let mut seal = ActiveSeal {
            key: seal_key(session.key().as_slice()),
            path: self.dir.user_file(user, UserFile::Seal),
            trusted_from: None,
        };
        let (check, last_verified, trusted_from) = self.check(&seal, user, vault_says_sealed);

        // the seal moves on either way, so a warning is given once and not at every login
        match (check, last_verified) {
            // the last line the check itself verified, not whatever was appended since
            (LogCheck::Clean { .. }, Some(last)) => {
                seal.trusted_from = trusted_from;
                let _ = write_seal(&seal, last);
            }
            (LogCheck::Clean { .. }, None) => {
                let _ = write_seal(&seal, (0, GENESIS));
            }
            // nothing was verified: seal whatever the log ends with now, and check from there next time. a broken chain stays broken, so without that the warning would come back at every login
            (LogCheck::Tampered(_), _) => {
                let last = self.last_line();
                seal.trusted_from = last;
                let _ = write_seal(&seal, last.unwrap_or((0, GENESIS)));
            }
        }
        *self.active_seal() = Some(seal);
        // logged after sealing starts, so the seal moves onto the warning itself
        if let LogCheck::Tampered(problem) = check {
            self.log(Some(user), Event::LogTamperDetected { problem });
        }
        check
    }

    // stops sealing; dropping the ActiveSeal wipes the key
    pub fn end_session(&self) {
        *self.active_seal() = None;
    }

    // also returns the last line of the verified chain, which is what a clean check seals, and the line the check started from if it didn't start at the beginning
    fn check(
        &self,
        seal: &ActiveSeal,
        user: &Username,
        vault_says_sealed: bool,
    ) -> (LogCheck, Option<LinePoint>, Option<LinePoint>) {
        let tampered = |problem| (LogCheck::Tampered(problem), None, None);
        // a seal that isn't genuine is reported first: it is what says where the check starts, so a forged one would otherwise show up as some other problem
        let stored = match read_seal(&seal.path) {
            Ok(None) => None,
            Ok(Some(stored)) => match authenticate_seal(seal, &stored) {
                Ok(authentic) => Some(authentic),
                Err(problem) => return tampered(problem),
            },
            Err(()) => return tampered(TamperProblem::SealMismatch),
        };
        let trusted_from = stored.as_ref().and_then(|s| s.trusted_from);
        let (entries, resumed) = match read_chain_from(&self.dir, trusted_from) {
            Ok(chain) => chain,
            Err(problem) => return tampered(problem),
        };
        let trusted_from = trusted_from.filter(|_| resumed);
        let last = entries.last().map(|e| (e.seq, e.hash)).or(trusted_from);
        let sealed_seq = match stored {
            // no seal yet: a first login, unless the vault says there was one
            None if !vault_says_sealed => {
                let clean = LogCheck::Clean {
                    failed_attempts_since_last_session: 0,
                };
                return (clean, last, None);
            }
            None => return tampered(TamperProblem::SealMismatch),
            Some(authentic) => match find_sealed(&authentic, &entries, trusted_from) {
                Ok(seq) => seq,
                Err(problem) => return tampered(problem),
            },
        };

        // only this user's own failures, and only those after their last session
        let failed = entries
            .iter()
            .filter(|e| e.seq > sealed_seq)
            .filter(|e| e.event == "unlock_failed" && e.user.as_deref() == Some(user.as_str()))
            .count();
        let clean = LogCheck::Clean {
            failed_attempts_since_last_session: u32::try_from(failed).unwrap_or(u32::MAX),
        };
        (clean, last, trusted_from)
    }

    fn last_line(&self) -> Option<LinePoint> {
        match tail(&self.log) {
            Ok(Some(tail)) => Some(tail.last),
            _ => tail(&self.rotated).ok().flatten().map(|t| t.last),
        }
    }
}

// HMAC-SHA256(vault key, context), as the spec gives it
fn seal_key(vault_key: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(vault_key)
        .unwrap_or_else(|_| unreachable!("hmac takes a key of any length"));
    mac.update(SEAL_CONTEXT);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn seal_mac(
    key: &[u8; 32],
    seq: u64,
    hash: &[u8; 32],
    trusted_from: Option<LinePoint>,
) -> HmacSha256 {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("hmac takes a key of any length"));
    mac.update(&seq.to_be_bytes());
    mac.update(hash);
    if let Some((from_seq, from_hash)) = trusted_from {
        mac.update(&from_seq.to_be_bytes());
        mac.update(&from_hash);
    }
    mac
}

fn write_seal(seal: &ActiveSeal, (seq, hash): (u64, [u8; 32])) -> io::Result<()> {
    let mac = seal_mac(&seal.key, seq, &hash, seal.trusted_from)
        .finalize()
        .into_bytes();
    let file = SealFile {
        seq,
        hash: hex::encode(hash),
        from_seq: seal.trusted_from.map(|(seq, _)| seq),
        from_hash: seal.trusted_from.map(|(_, hash)| hex::encode(hash)),
        mac: hex::encode(mac),
    };
    let bytes = serde_json::to_vec(&file).map_err(io::Error::other)?;
    write_atomically(&seal.path, &bytes, true)
}

// Ok(None): there is no seal. Err: there is something, but it isn't a seal
fn read_seal(path: &Path) -> Result<Option<SealFile>, ()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Ok(meta) if meta.is_file() && meta.len() <= MAX_SEAL_BYTES => {}
        _ => return Err(()),
    }
    let bytes = fs::read(path).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map(Some).map_err(|_| ())
}

// the mac first, so nothing in an unauthenticated seal is trusted
fn authenticate_seal(seal: &ActiveSeal, stored: &SealFile) -> Result<AuthenticSeal, TamperProblem> {
    let hash = decode_hash(&stored.hash)?;
    let trusted_from = match (stored.from_seq, &stored.from_hash) {
        (None, None) => None,
        (Some(seq), Some(hash)) => Some((seq, decode_hash(hash)?)),
        _ => return Err(TamperProblem::SealMismatch),
    };
    let mut mac = [0u8; 32];
    hex::decode_to_slice(&stored.mac, &mut mac).map_err(|_| TamperProblem::SealMismatch)?;
    // verify_slice compares in constant time
    seal_mac(&seal.key, stored.seq, &hash, trusted_from)
        .verify_slice(&mac)
        .map_err(|_| TamperProblem::SealMismatch)?;
    Ok(AuthenticSeal {
        seq: stored.seq,
        hash,
        trusted_from,
    })
}

fn decode_hash(text: &str) -> Result<[u8; 32], TamperProblem> {
    let mut hash = [0u8; 32];
    hex::decode_to_slice(text, &mut hash).map_err(|_| TamperProblem::SealMismatch)?;
    Ok(hash)
}

// the sealed line must still be in the log, unchanged. returns its seq
fn find_sealed(
    seal: &AuthenticSeal,
    entries: &[Entry],
    trusted_from: Option<LinePoint>,
) -> Result<u64, TamperProblem> {
    // seq 0 is a seal over an empty log
    if seal.seq == 0 {
        return if seal.hash == GENESIS {
            Ok(0)
        } else {
            Err(TamperProblem::SealMismatch)
        };
    }
    if trusted_from == Some((seal.seq, seal.hash)) {
        return Ok(seal.seq);
    }
    match entries.iter().find(|e| e.seq == seal.seq) {
        None => Err(TamperProblem::SealedEntryMissing),
        Some(entry) if entry.hash != seal.hash => Err(TamperProblem::SealMismatch),
        Some(_) => Ok(seal.seq),
    }
}

fn wait_for_lock(file: &File) -> io::Result<()> {
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(LOCK_RETRY);
            }
            Err(fs::TryLockError::WouldBlock) => return Err(io::ErrorKind::WouldBlock.into()),
            Err(fs::TryLockError::Error(e)) => return Err(e),
        }
    }
}

// append mode, 0600 when created, and never through a symlink
fn open_private(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    options.open(path)
}

struct Tail {
    // seq of the last line that parses, and the hash of the last line's exact bytes
    last: (u64, [u8; 32]),
    terminated: bool,
}

// reads only the end of the file: the last line is all an append needs
fn tail(path: &Path) -> io::Result<Option<Tail>> {
    let meta = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        result => result?,
    };
    if !meta.is_file() {
        return Err(io::Error::other("log is not a regular file"));
    }
    if meta.len() == 0 {
        return Ok(None);
    }
    let start = meta.len().saturating_sub(TAIL_BYTES);
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(TAIL_BYTES).read_to_end(&mut bytes)?;

    let terminated = bytes.last() == Some(&b'\n');
    let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let mut lines: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
    // reading from the middle of the file starts mid-line
    if start > 0 && lines.len() > 1 {
        lines.remove(0);
    }
    let Some(last) = lines.last() else {
        return Ok(None);
    };
    // a damaged last line still gets linked to; its seq comes from the nearest good line
    let seq = lines
        .iter()
        .rev()
        .find_map(|line| serde_json::from_slice::<Stored>(line).ok())
        .map_or(0, |stored| stored.seq);
    Ok(Some(Tail {
        last: (seq, sha256(last)),
        terminated,
    }))
}

pub(crate) struct Entry {
    pub seq: u64,
    pub hash: [u8; 32],
    pub user: Option<String>,
    pub event: String,
}

// the whole log from the first line, with no trust point; only the tests still need that
#[cfg(test)]
pub(crate) fn read_chain(dir: &DataDir) -> Result<Vec<Entry>, TamperProblem> {
    read_chain_from(dir, None).map(|(entries, _)| entries)
}

// events.log.1 then events.log, every seq and prev link checked. with a trust point (a break the user was already warned about), the check starts after the line with that hash, as if it were the start of the log; if that line is gone, the whole log is checked as usual. also says whether it started there
fn read_chain_from(
    dir: &DataDir,
    trusted_from: Option<LinePoint>,
) -> Result<(Vec<Entry>, bool), TamperProblem> {
    // each line with its hash, and whether its file may start after seq 1
    let mut lines: Vec<(Vec<u8>, [u8; 32], bool)> = Vec::new();
    // only events.log.1 may start after seq 1: its predecessors rotated away. events.log starts late only after a rotation, so without a rotated file it must begin at the very first line, or the front was cut off
    for (path, may_start_late) in [(dir.rotated_log_file(), true), (dir.log_file(), false)] {
        let Some(bytes) = read_log(&path)? else {
            continue;
        };
        let Some(body) = bytes.strip_suffix(b"\n") else {
            // empty is fine; anything else must end with a complete line
            if bytes.is_empty() {
                continue;
            }
            return Err(TamperProblem::ChainBroken);
        };
        for line in body.split(|b| *b == b'\n') {
            lines.push((line.to_vec(), sha256(line), may_start_late));
        }
    }

    let resume_at = trusted_from
        .and_then(|(_, hash)| lines.iter().position(|(_, h, _)| *h == hash))
        .map(|i| i + 1);
    let mut before = match resume_at {
        Some(_) => trusted_from,
        None => None,
    };
    let mut entries: Vec<Entry> = Vec::new();
    for (line, hash, may_start_late) in &lines[resume_at.unwrap_or(0)..] {
        let stored: Stored =
            serde_json::from_slice(line).map_err(|_| TamperProblem::ChainBroken)?;
        // compared as text, in the exact form hex() writes, so each hash has one spelling
        let linked = match before {
            Some((seq, hash)) => stored.seq == seq + 1 && stored.prev == hex::encode(hash),
            None => {
                let first_ever = stored.seq == 1 && stored.prev == hex::encode(GENESIS);
                first_ever || (*may_start_late && stored.seq > 1)
            }
        };
        if !linked {
            return Err(TamperProblem::ChainBroken);
        }
        before = Some((stored.seq, *hash));
        entries.push(Entry {
            seq: stored.seq,
            hash: *hash,
            user: stored.user,
            event: stored.event,
        });
    }
    Ok((entries, resume_at.is_some()))
}

fn read_log(path: &Path) -> Result<Option<Vec<u8>>, TamperProblem> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Ok(meta) if meta.is_file() && meta.len() <= MAX_READ_BYTES => fs::read(path)
            .map(Some)
            .map_err(|_| TamperProblem::ChainBroken),
        _ => Err(TamperProblem::ChainBroken),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
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
    // --- the seal (task 9) ---

    const PW: &str = "correct horse battery";

    // a real user with an open session, as after a successful login
    fn session(data: &DataDir, name: &str) -> Session {
        crate::vault::storage::create_user_with_params(
            data,
            &user(name),
            PW,
            crate::vault::crypto::KdfParams::TEST,
        )
        .unwrap()
    }

    fn seal_path(data: &DataDir, name: &str) -> PathBuf {
        data.user_file(&user(name), crate::paths::UserFile::Seal)
    }

    fn read_seal(data: &DataDir, name: &str) -> Value {
        serde_json::from_slice(&fs::read(seal_path(data, name)).unwrap()).unwrap()
    }

    fn clean(n: u32) -> LogCheck {
        LogCheck::Clean {
            failed_attempts_since_last_session: n,
        }
    }

    // one run of the app for alice: log in, a few events, log out. leaves alice's seal on the
    // last line of the log
    fn sealed_history(data: &DataDir, alice: &Session) {
        let logger = Logger::open(data, clock);
        logger.log(None, Event::AppStart);
        logger.begin_session(alice, false);
        for event in [
            Event::UnlockSucceeded,
            Event::CredentialAdded,
            Event::CredentialsListed,
            Event::PasswordCopied,
        ] {
            logger.log(Some(&user("alice")), event);
        }
        logger.end_session();
    }

    // what someone who can write the file but doesn't know the password can do: change a line
    // and recompute every prev after it, so the chain itself looks intact
    fn rechain(lines: &mut [String]) {
        for i in 1..lines.len() {
            let prev = sha_hex(&lines[i - 1]);
            let mut json: Value = serde_json::from_str(&lines[i]).unwrap();
            json["prev"] = prev.into();
            lines[i] = serde_json::to_string(&json).unwrap();
        }
    }

    // nothing to compare against yet: the first login is clean and leaves a private seal
    #[test]
    fn first_session_is_clean() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let logger = Logger::open(&data, clock);
        logger.log(None, Event::AppStart);

        assert_eq!(logger.begin_session(&alice, false), clean(0));

        assert!(seal_path(&data, "alice").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(seal_path(&data, "alice"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    // a log nobody touched verifies at the next login, with other runs in between
    #[test]
    fn untouched_log_verifies_next_time() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        sealed_history(&data, &alice);
        Logger::open(&data, clock).log(None, Event::AppStart);

        let logger = Logger::open(&data, clock);

        assert_eq!(logger.begin_session(&alice, true), clean(0));
    }

    // while a session is open the seal always points at the newest line; after it ends,
    // other events no longer move it
    #[test]
    fn seal_follows_every_event() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let logger = Logger::open(&data, clock);
        logger.log(None, Event::AppStart);
        logger.begin_session(&alice, false);

        for _ in 0..5 {
            logger.log(Some(&user("alice")), Event::CredentialAdded);
            let last = lines(&data.log_file()).pop().unwrap();
            let last_json: Value = serde_json::from_str(&last).unwrap();
            let seal = read_seal(&data, "alice");
            assert_eq!(seal["seq"], last_json["seq"]);
            assert_eq!(seal["hash"], sha_hex(&last).as_str());
            let mut keys: Vec<_> = seal.as_object().unwrap().keys().cloned().collect();
            keys.sort();
            assert_eq!(keys, ["hash", "mac", "seq"]);
        }

        logger.end_session();
        let sealed = fs::read(seal_path(&data, "alice")).unwrap();
        logger.log(None, Event::AppExit { code: 0 });
        assert_eq!(fs::read(seal_path(&data, "alice")).unwrap(), sealed);
    }

    // every change to what alice sealed is caught at her next login, including the one the
    // chain alone misses: an edit with every later link recomputed
    #[test]
    fn sealed_history_edits_are_detected() {
        type Edit = fn(&DataDir, &mut Vec<String>);
        let cases: [(&str, Edit, Option<TamperProblem>); 7] = [
            (
                "byte changed in a middle line",
                |_, l| l[2] = l[2].replacen(&TS.to_string(), &(TS + 1).to_string(), 1),
                None,
            ),
            (
                "byte changed in the sealed line",
                |_, l| {
                    let last = l.len() - 1;
                    l[last] = l[last].replacen(&TS.to_string(), &(TS + 1).to_string(), 1);
                },
                Some(TamperProblem::SealMismatch),
            ),
            (
                "edited and rechained",
                |_, l| {
                    l[2] = l[2].replace("credential_added", "credentials_listed");
                    rechain(l);
                },
                Some(TamperProblem::SealMismatch),
            ),
            (
                "sealed line deleted",
                |_, l| {
                    l.pop();
                },
                Some(TamperProblem::SealedEntryMissing),
            ),
            ("lines swapped", |_, l| l.swap(2, 3), None),
            (
                "truncated before the seal",
                |_, l| l.truncate(2),
                Some(TamperProblem::SealedEntryMissing),
            ),
            (
                "log deleted",
                |data, l| {
                    l.clear();
                    fs::remove_file(data.log_file()).unwrap();
                },
                Some(TamperProblem::SealedEntryMissing),
            ),
        ];
        for (name, edit, expected) in cases {
            let (_dir, data) = data_dir();
            let alice = session(&data, "alice");
            sealed_history(&data, &alice);
            let mut lines = lines(&data.log_file());
            edit(&data, &mut lines);
            if !lines.is_empty() {
                write_lines(&data.log_file(), &lines);
            }

            let check = Logger::open(&data, clock).begin_session(&alice, true);

            match expected {
                Some(problem) => assert_eq!(check, LogCheck::Tampered(problem), "{name}"),
                None => assert!(matches!(check, LogCheck::Tampered(_)), "{name}: {check:?}"),
            }
        }
    }

    // deleting the seal must not pass for a first login: the vault remembers there was one
    #[test]
    fn deleted_seal_is_detected() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        sealed_history(&data, &alice);
        fs::remove_file(seal_path(&data, "alice")).unwrap();

        let check = Logger::open(&data, clock).begin_session(&alice, true);

        assert_eq!(check, LogCheck::Tampered(TamperProblem::SealMismatch));
    }

    // a seal without the right mac, or one that isn't a seal at all, is refused
    #[test]
    fn forged_seal_is_detected() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        sealed_history(&data, &alice);
        let mut seal = read_seal(&data, "alice");
        seal["mac"] = ZEROS.into();

        for forged in [serde_json::to_vec(&seal).unwrap(), b"garbage".to_vec()] {
            fs::write(seal_path(&data, "alice"), forged).unwrap();
            set_mode(&seal_path(&data, "alice"), 0o600);

            let check = Logger::open(&data, clock).begin_session(&alice, true);

            assert_eq!(check, LogCheck::Tampered(TamperProblem::SealMismatch));
        }
    }

    // each user's seal key comes from their own vault key, so alice's seal means nothing to bob
    #[test]
    fn another_users_seal_does_not_verify() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let bob = session(&data, "bob");
        sealed_history(&data, &alice);
        fs::copy(seal_path(&data, "alice"), seal_path(&data, "bob")).unwrap();

        let check = Logger::open(&data, clock).begin_session(&bob, true);

        assert_eq!(check, LogCheck::Tampered(TamperProblem::SealMismatch));
    }

    // lines added after alice's session, chained correctly, are accepted: other users and
    // failed logins write there. this is the documented limit of the seal
    #[test]
    fn entries_after_the_seal_are_accepted() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        sealed_history(&data, &alice);
        let other = Logger::open(&data, clock);
        for _ in 0..3 {
            other.log(Some(&user("bob")), Event::CredentialAdded);
        }

        let check = Logger::open(&data, clock).begin_session(&alice, true);

        assert_eq!(check, clean(0));
    }

    // alice is told how often someone tried her password while she was away: only her own
    // failures, and only since her last session
    #[test]
    fn failed_attempts_are_counted() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let bad = |failures| Event::UnlockFailed(UnlockFailure::BadCredentials { failures });
        Logger::open(&data, clock).log(Some(&user("alice")), bad(1)); // before her last session
        sealed_history(&data, &alice);

        let other = Logger::open(&data, clock);
        other.log(Some(&user("alice")), bad(1));
        other.log(Some(&user("bob")), bad(1));
        other.log(None, Event::UnlockFailed(UnlockFailure::UnknownUser));
        other.log(Some(&user("alice")), Event::CredentialsListed);
        other.log(Some(&user("alice")), bad(2));

        let check = Logger::open(&data, clock).begin_session(&alice, true);

        assert_eq!(check, clean(2));
    }

    // a detected change is logged once, and the seal moves on, so the same warning doesn't
    // come back at every login
    #[test]
    fn tamper_warning_does_not_repeat() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        sealed_history(&data, &alice);
        let mut lines = lines(&data.log_file());
        lines[2] = lines[2].replace("credential_added", "credentials_listed");
        rechain(&mut lines);
        write_lines(&data.log_file(), &lines);

        let logger = Logger::open(&data, clock);
        assert_eq!(
            logger.begin_session(&alice, true),
            LogCheck::Tampered(TamperProblem::SealMismatch)
        );
        let last = lines_after(&data);
        assert_eq!(last["event"], "log_tamper_detected");
        assert_eq!(last["problem"], "seal_mismatch");
        assert_eq!(last["user"], "alice");
        logger.end_session();

        let check = Logger::open(&data, clock).begin_session(&alice, true);

        assert_eq!(check, clean(0));
    }

    fn lines_after(data: &DataDir) -> Value {
        serde_json::from_str(&lines(&data.log_file()).pop().unwrap()).unwrap()
    }

    // a long absence rotates the sealed line out of both files; the check says so rather than
    // passing or crashing
    #[test]
    fn sealed_entry_rotated_away() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let logger = Logger::open_with_limit(&data, clock, 400);
        logger.log(None, Event::AppStart);
        logger.begin_session(&alice, false);
        logger.log(Some(&user("alice")), Event::CredentialAdded);
        logger.end_session();
        let other = Logger::open_with_limit(&data, clock, 400);
        for _ in 0..30 {
            other.log(Some(&user("bob")), Event::CredentialsListed);
        }

        let check = Logger::open_with_limit(&data, clock, 400).begin_session(&alice, true);

        assert_eq!(check, LogCheck::Tampered(TamperProblem::SealedEntryMissing));
    }

    // with nothing rotated, the log must start at the first line ever written: cutting lines off the front leaves every remaining link intact, so only the missing start can show it
    #[test]
    fn cut_off_start_of_the_log_is_detected() {
        let (_dir, data) = data_dir();
        let logger = Logger::open(&data, clock);
        for _ in 0..5 {
            logger.log(Some(&user("alice")), Event::CredentialAdded);
        }
        let mut kept = lines(&data.log_file());
        kept.drain(..2);
        write_lines(&data.log_file(), &kept);

        assert_eq!(read_chain(&data).err(), Some(TamperProblem::ChainBroken));
    }

    // the red-team case: lines before alice's sealed one are deleted. her sealed line is still there and still verifies, so the seal alone doesn't notice
    #[test]
    fn cut_off_start_is_reported_at_login() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let logger = Logger::open(&data, clock);
        for _ in 0..3 {
            logger.log(Some(&user("bob")), Event::CredentialsListed);
        }
        sealed_history(&data, &alice);
        let mut kept = lines(&data.log_file());
        kept.drain(..2);
        write_lines(&data.log_file(), &kept);

        let check = Logger::open(&data, clock).begin_session(&alice, true);

        assert_eq!(check, LogCheck::Tampered(TamperProblem::ChainBroken));
    }

    // lines before alice's sealed one are cut off, so the chain is broken for everyone from now on
    fn cut_front(data: &DataDir) {
        let mut kept = lines(&data.log_file());
        kept.drain(..2);
        write_lines(&data.log_file(), &kept);
    }

    // a broken chain stays broken, warning only once

    #[test]
    fn broken_chain_warning_is_given_once() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let logger = Logger::open(&data, clock);
        for _ in 0..3 {
            logger.log(Some(&user("bob")), Event::CredentialsListed);
        }
        sealed_history(&data, &alice);
        cut_front(&data);

        let logger = Logger::open(&data, clock);
        assert_eq!(
            logger.begin_session(&alice, true),
            LogCheck::Tampered(TamperProblem::ChainBroken)
        );
        logger.end_session();

        let check = Logger::open(&data, clock).begin_session(&alice, true);

        assert_eq!(check, clean(0));
    }

    // only the break alice was warned about is accepted: a new one after the warning is reported again
    #[test]
    fn new_break_after_the_warning_is_reported() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let logger = Logger::open(&data, clock);
        for _ in 0..3 {
            logger.log(Some(&user("bob")), Event::CredentialsListed);
        }
        sealed_history(&data, &alice);
        cut_front(&data);
        let logger = Logger::open(&data, clock);
        logger.begin_session(&alice, true);
        for _ in 0..3 {
            logger.log(Some(&user("alice")), Event::CredentialsListed);
        }
        logger.end_session();
        let mut lines = lines(&data.log_file());
        let second_last = lines.len() - 2;
        lines.remove(second_last);
        write_lines(&data.log_file(), &lines);

        let check = Logger::open(&data, clock).begin_session(&alice, true);

        assert!(matches!(check, LogCheck::Tampered(_)), "{check:?}");
    }

    // the warning is remembered per user: bob hasn't seen it yet, so he still gets it, once
    #[test]
    fn each_user_is_warned_once_about_a_break() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let bob = session(&data, "bob");
        let logger = Logger::open(&data, clock);
        for _ in 0..3 {
            logger.log(None, Event::AppStart);
        }
        logger.begin_session(&bob, false);
        logger.log(Some(&user("bob")), Event::CredentialsListed);
        logger.end_session();
        sealed_history(&data, &alice);
        let mut lines = lines(&data.log_file());
        lines.remove(1);
        write_lines(&data.log_file(), &lines);

        for who in [&alice, &bob] {
            let logger = Logger::open(&data, clock);
            assert_eq!(
                logger.begin_session(who, true),
                LogCheck::Tampered(TamperProblem::ChainBroken),
                "{}",
                who.user().as_str()
            );
            logger.end_session();
            let logger = Logger::open(&data, clock);
            assert_eq!(
                logger.begin_session(who, true),
                clean(0),
                "{}",
                who.user().as_str()
            );
            logger.end_session();
        }
    }

    // the warning line is where the accepted part ends; deleting it must not make the old break disappear
    #[test]
    fn deleting_the_warning_brings_the_warning_back() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let logger = Logger::open(&data, clock);
        for _ in 0..3 {
            logger.log(Some(&user("bob")), Event::CredentialsListed);
        }
        sealed_history(&data, &alice);
        cut_front(&data);
        let logger = Logger::open(&data, clock);
        logger.begin_session(&alice, true);
        logger.log(Some(&user("alice")), Event::CredentialsListed);
        logger.end_session();
        let kept: Vec<String> = lines(&data.log_file())
            .into_iter()
            .filter(|l| !l.contains("log_tamper_detected"))
            .collect();
        write_lines(&data.log_file(), &kept);

        let check = Logger::open(&data, clock).begin_session(&alice, true);

        assert!(matches!(check, LogCheck::Tampered(_)), "{check:?}");
    }

    // once a break was accepted the seal says where trust starts again, and that is covered by the mac like everything else in it
    #[test]
    fn every_field_of_the_seal_is_authenticated() {
        let (_dir, data) = data_dir();
        let alice = session(&data, "alice");
        let logger = Logger::open(&data, clock);
        for _ in 0..3 {
            logger.log(Some(&user("bob")), Event::CredentialsListed);
        }
        sealed_history(&data, &alice);
        cut_front(&data);
        let logger = Logger::open(&data, clock);
        logger.begin_session(&alice, true);
        logger.end_session();
        let original = read_seal(&data, "alice");
        let fields = original.as_object().unwrap();
        assert!(
            fields.len() > 3,
            "the seal should also remember the accepted break: {original}"
        );

        for name in fields.keys().filter(|k| k.as_str() != "mac") {
            let mut seal = original.clone();
            seal[name] = match &seal[name] {
                Value::Number(n) => (n.as_u64().unwrap() + 1).into(),
                Value::String(s) => {
                    let flipped = if s.starts_with('0') { "1" } else { "0" };
                    format!("{flipped}{}", &s[1..]).into()
                }
                other => panic!("{name}: unexpected {other}"),
            };
            fs::write(
                seal_path(&data, "alice"),
                serde_json::to_vec(&seal).unwrap(),
            )
            .unwrap();
            set_mode(&seal_path(&data, "alice"), 0o600);

            let check = Logger::open(&data, clock).begin_session(&alice, true);

            assert_eq!(
                check,
                LogCheck::Tampered(TamperProblem::SealMismatch),
                "{name}"
            );
        }
    }

    // logging is best-effort: another process holding the append lock must not hang the app. after a short wait the line is dropped, and logging works again once the lock is free
    #[test]
    fn held_append_lock_does_not_hang() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (_dir, data) = data_dir();
        let logger = Logger::open(&data, clock);
        // the first event creates the lock file the way the app does
        logger.log(None, Event::AppStart);
        let holder = fs::OpenOptions::new()
            .write(true)
            .open(data.log_file().with_extension("log.lock"))
            .unwrap();
        holder.lock().unwrap();

        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            logger.log(None, Event::AppExit { code: 0 });
            let _ = done.send(());
        });

        assert!(
            finished.recv_timeout(Duration::from_secs(5)).is_ok(),
            "log() is still waiting for the lock"
        );
        assert_eq!(lines(&data.log_file()).len(), 1);
        drop(holder);
        Logger::open(&data, clock).log(None, Event::AppExit { code: 0 });
        assert_eq!(lines(&data.log_file()).len(), 2);
    }
}
