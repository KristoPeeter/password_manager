// the login flow (task 7) is the only caller; until then only the tests use this module
#![allow(dead_code)]

use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

use serde::{Deserialize, Serialize};

use super::storage::write_atomically;

const LOCK_AFTER: u32 = 3;
const BASE_COOLDOWN: u64 = 30;
const MAX_COOLDOWN: u64 = 900;
// the first count whose cooldown reaches the cap (30 s × 2^5 = 960 s)
const MAX_LEVEL: u32 = 8;
// the real file is about 50 bytes; anything far bigger is damage, not a count
const MAX_FILE_BYTES: u64 = 1024;

#[derive(Debug, PartialEq)]
pub enum LockState {
    Open,
    Locked { remaining_secs: u64 },
}

// what one more wrong password did. locked_secs is Some when this failure started or extended
// a lock, so the caller knows when to log lockout_started
#[derive(Debug, PartialEq)]
pub struct Failure {
    pub failures: u32,
    pub locked_secs: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempts {
    failures: u32,
    last_failure: u64,
}

enum Stored {
    Missing,
    Found(Attempts),
    Damaged, // unreadable, oversized, not a regular file, or not the expected json
}

// 0 below 3 failures, then 30 s doubling each time, capped at 15 minutes. the shift is capped
// first: 30 << 5 is already past the cap, and a large shift would silently lose bits
pub fn cooldown_secs(failures: u32) -> u64 {
    if failures < LOCK_AFTER {
        return 0;
    }
    let doublings = (failures - LOCK_AFTER).min(5);
    (BASE_COOLDOWN << doublings).min(MAX_COOLDOWN)
}

pub fn state(path: &Path, now: u64) -> LockState {
    let attempts = match read(path) {
        Stored::Missing => return LockState::Open,
        Stored::Found(attempts) => attempts,
        Stored::Damaged => {
            // damaging the file must cost the attacker, not reset the count
            let attempts = Attempts {
                failures: MAX_LEVEL,
                last_failure: now,
            };
            // the lock holds for this call even if the repair can't be written
            let _ = write(path, &attempts);
            attempts
        }
    };
    lock_state(&attempts, now)
}

pub fn record_failure(path: &Path, now: u64) -> io::Result<Failure> {
    let previous = match read(path) {
        Stored::Missing => 0,
        Stored::Found(attempts) => attempts.failures,
        Stored::Damaged => MAX_LEVEL,
    };
    let failures = previous.saturating_add(1);
    write(
        path,
        &Attempts {
            failures,
            last_failure: now,
        },
    )?;
    let cooldown = cooldown_secs(failures);
    Ok(Failure {
        failures,
        locked_secs: (cooldown > 0).then_some(cooldown),
    })
}

// a missing file is Ok: there was nothing to clear
pub fn clear(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

// only subtraction, never last_failure + cooldown, so no timestamp can overflow
fn lock_state(attempts: &Attempts, now: u64) -> LockState {
    let cooldown = cooldown_secs(attempts.failures);
    if cooldown == 0 {
        return LockState::Open;
    }
    // a clock earlier than the last failure can't measure the wait, so the full lock applies
    let Some(elapsed) = now.checked_sub(attempts.last_failure) else {
        return LockState::Locked {
            remaining_secs: cooldown,
        };
    };
    if elapsed >= cooldown {
        LockState::Open
    } else {
        LockState::Locked {
            remaining_secs: cooldown - elapsed,
        }
    }
}

fn read(path: &Path) -> Stored {
    // checked before open: opening a fifo would block, and a link could point anywhere
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Stored::Missing,
        Ok(meta) if meta.is_file() => {}
        _ => return Stored::Damaged,
    }
    let Ok(file) = File::open(path) else {
        return Stored::Damaged;
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_FILE_BYTES
    {
        return Stored::Damaged;
    }
    serde_json::from_slice(&bytes).map_or(Stored::Damaged, Stored::Found)
}

fn write(path: &Path, attempts: &Attempts) -> io::Result<()> {
    let bytes = serde_json::to_vec(attempts).map_err(io::Error::other)?;
    write_atomically(path, &bytes, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const NOW: u64 = 1_700_000_000;
    const MAX_COOLDOWN: u64 = 900;

    // the TempDir must stay alive as long as the path is used
    fn attempts_file() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attempts.json");
        (dir, path)
    }

    fn fail_times(path: &Path, times: u32, now: u64) -> Failure {
        let mut last = None;
        for _ in 0..times {
            last = Some(record_failure(path, now).unwrap());
        }
        last.unwrap()
    }

    fn read_json(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    // --- cooldown maths ---

    // 30 s at the third failure, doubling each time, never past 15 minutes, and no overflow
    // however many failures pile up
    #[test]
    fn cooldown_table() {
        for (failures, secs) in [
            (0, 0),
            (1, 0),
            (2, 0),
            (3, 30),
            (4, 60),
            (5, 120),
            (6, 240),
            (7, 480),
            (8, 900),
            (9, 900),
            (64, 900),
            (u32::MAX, 900),
        ] {
            assert_eq!(cooldown_secs(failures), secs, "{failures} failures");
        }
    }

    // --- counting failures ---

    // a typo or two must not lock anyone out
    #[test]
    fn two_failures_stay_open() {
        let (_dir, path) = attempts_file();

        assert_eq!(
            record_failure(&path, NOW).unwrap(),
            Failure {
                failures: 1,
                locked_secs: None
            }
        );
        assert_eq!(
            record_failure(&path, NOW).unwrap(),
            Failure {
                failures: 2,
                locked_secs: None
            }
        );
        assert_eq!(state(&path, NOW), LockState::Open);
    }

    // the lock counts down from the third failure and ends exactly when the cooldown does
    #[test]
    fn third_failure_locks_for_30s() {
        let (_dir, path) = attempts_file();

        let third = fail_times(&path, 3, NOW);

        assert_eq!(
            third,
            Failure {
                failures: 3,
                locked_secs: Some(30)
            }
        );
        assert_eq!(state(&path, NOW), LockState::Locked { remaining_secs: 30 });
        assert_eq!(
            state(&path, NOW + 29),
            LockState::Locked { remaining_secs: 1 }
        );
        assert_eq!(state(&path, NOW + 30), LockState::Open);
    }

    // a wrong password right after a lock ends earns a longer one
    #[test]
    fn failure_after_cooldown_doubles_it() {
        let (_dir, path) = attempts_file();
        fail_times(&path, 3, NOW);

        let fourth = record_failure(&path, NOW + 30).unwrap();

        assert_eq!(
            fourth,
            Failure {
                failures: 4,
                locked_secs: Some(60)
            }
        );
        assert_eq!(
            state(&path, NOW + 30),
            LockState::Locked { remaining_secs: 60 }
        );
    }

    // a successful login wipes the slate
    #[test]
    fn clear_resets() {
        let (_dir, path) = attempts_file();
        fail_times(&path, 3, NOW);

        clear(&path).unwrap();

        assert!(!path.exists());
        assert_eq!(state(&path, NOW), LockState::Open);
        assert_eq!(record_failure(&path, NOW).unwrap().failures, 1);
    }

    // clearing a user who never failed is not an error
    #[test]
    fn clear_without_a_file_is_ok() {
        let (_dir, path) = attempts_file();

        clear(&path).unwrap();
    }

    // --- persistence ---

    // the count lives on disk, not in the process: quitting and restarting the app must not
    // reset it. the file holds exactly the two documented fields
    #[test]
    fn state_survives_a_fresh_read() {
        let (_dir, path) = attempts_file();
        fail_times(&path, 3, NOW);

        let json = read_json(&path);
        assert_eq!(
            json,
            serde_json::json!({ "failures": 3, "last_failure": NOW })
        );

        let reopened = path.clone();
        assert_eq!(
            state(&reopened, NOW + 10),
            LockState::Locked { remaining_secs: 20 }
        );
    }

    // --- damaged files and clocks ---

    // damaging the file must cost the attacker, not reset the count: anything unreadable means
    // the maximum lock, and the file is rewritten so the lock holds on the next read too
    #[test]
    fn corrupt_file_locks_for_the_maximum() {
        let oversized = vec![b' '; 1024 * 1024];
        let cases: [(&str, &[u8]); 7] = [
            ("garbage", b"\x00\xffnot json"),
            ("empty", b""),
            ("wrong shape", b"[1, 2, 3]"),
            ("missing field", br#"{ "failures": 1 }"#),
            (
                "unknown field",
                br#"{ "failures": 1, "last_failure": 5, "extra": 0 }"#,
            ),
            ("negative", br#"{ "failures": -1, "last_failure": 5 }"#),
            (
                "over u32",
                br#"{ "failures": 4294967296, "last_failure": 5 }"#,
            ),
        ];
        let oversized_case: (&str, &[u8]) = ("oversized", &oversized);
        for (name, bytes) in cases.into_iter().chain([oversized_case]) {
            let (_dir, path) = attempts_file();
            fs::write(&path, bytes).unwrap();

            assert_eq!(
                state(&path, NOW),
                LockState::Locked {
                    remaining_secs: MAX_COOLDOWN
                },
                "{name}"
            );
            assert_eq!(
                read_json(&path),
                serde_json::json!({ "failures": 8, "last_failure": NOW }),
                "{name}: file not repaired"
            );
            assert_eq!(
                state(&path, NOW + 1),
                LockState::Locked {
                    remaining_secs: MAX_COOLDOWN - 1
                },
                "{name}"
            );
        }
    }

    // a wrong password on a damaged file counts on from the maximum, never from zero
    #[test]
    fn failure_on_a_corrupt_file_counts_from_the_maximum() {
        let (_dir, path) = attempts_file();
        fs::write(&path, b"garbage").unwrap();

        let failure = record_failure(&path, NOW).unwrap();

        assert_eq!(
            failure,
            Failure {
                failures: 9,
                locked_secs: Some(MAX_COOLDOWN)
            }
        );
    }

    // setting the clock back must not shorten or skip a lock
    #[test]
    fn clock_set_backwards_stays_locked() {
        let (_dir, path) = attempts_file();
        fail_times(&path, 4, NOW);

        assert_eq!(
            state(&path, NOW - 3600),
            LockState::Locked { remaining_secs: 60 }
        );
    }

    // last_failure + cooldown must not overflow, whatever time the file claims
    #[test]
    fn huge_timestamps_do_not_overflow() {
        let (_dir, path) = attempts_file();
        fail_times(&path, 3, u64::MAX);

        assert!(matches!(state(&path, u64::MAX), LockState::Locked { .. }));
    }

    // --- the file itself ---

    // the count says when a user last failed; other local users have no business reading it
    #[cfg(unix)]
    #[test]
    fn attempts_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = attempts_file();

        record_failure(&path, NOW).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // written atomically: no temp file is left next to it after a write or a repair
    #[test]
    fn writes_leave_no_temp_files() {
        let (dir, path) = attempts_file();
        fail_times(&path, 3, NOW);
        fs::write(&path, b"garbage").unwrap();
        state(&path, NOW);

        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["attempts.json"]);
    }
}
