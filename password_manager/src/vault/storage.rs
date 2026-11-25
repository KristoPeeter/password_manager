use std::{fmt, fs, io, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::crypto::{self, KdfParams, Key, NONCE_LEN, SALT_LEN};

use super::models::Vault;
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const VERSION: u32 = 1;
const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB MAX for file sizes

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    NotFound,
    Unlock,
    TooLarge,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "Could not access vault file: {}", e),
            StorageError::NotFound => write!(f, "No vault found"),
            StorageError::Unlock => write!(f, "Couldn't unlock vault"),
            StorageError::TooLarge => write!(f, "Vault is too large to save"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            StorageError::NotFound
        } else {
            StorageError::Io(e)
        }
    }
}

pub struct SessionKey {
    key: Key,
    salt: [u8; SALT_LEN],
    params: KdfParams,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    kdf: KdfParams,
    salt: String,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultFile {
    header: Header,
    ciphertext: String,
}

fn decode<const N: usize>(s: &str) -> Result<[u8; N], StorageError> {
    B64.decode(s)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StorageError::Unlock)
}

fn read_file(path: &Path) -> Result<VaultFile, StorageError> {
    // checked before open: opening a fifo blocks until something writes to it
    if !fs::metadata(path)?.is_file() {
        return Err(io::Error::other("not a regular file").into());
    }
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file").into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(StorageError::Unlock);
    }
    let file: VaultFile = serde_json::from_slice(&bytes).map_err(|_| StorageError::Unlock)?;
    if file.header.version != VERSION || !file.header.kdf.is_within_bounds() {
        return Err(StorageError::Unlock);
    }
    Ok(file)
}

fn decrypt_vault(file: &VaultFile, key: &Key) -> Result<Vault, StorageError> {
    let nonce = decode::<NONCE_LEN>(&file.header.nonce)?;
    let ciphertext = B64
        .decode(&file.ciphertext)
        .map_err(|_| StorageError::Unlock)?;
    let aad = serde_json::to_vec(&file.header).map_err(|_| StorageError::Unlock)?;
    let plaintext =
        crypto::decrypt(key, &nonce, &aad, &ciphertext).map_err(|_| StorageError::Unlock)?;
    serde_json::from_slice(&plaintext).map_err(|_| StorageError::Unlock)
}

fn encrypt_vault(vault: &Vault, session: &SessionKey) -> Result<Vec<u8>, StorageError> {
    // a fresh nonce on every save, reusing one with the same key breaks aes-gcm
    let nonce = crypto::random_bytes::<NONCE_LEN>();
    let header = Header {
        version: VERSION,
        kdf: session.params,
        salt: B64.encode(session.salt),
        nonce: B64.encode(nonce),
    };
    let aad = serde_json::to_vec(&header).map_err(|_| StorageError::Unlock)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(vault).map_err(|_| StorageError::Unlock)?);
    let ciphertext = crypto::encrypt(&session.key, &nonce, &aad, &plaintext)
        .map_err(|_| StorageError::Unlock)?;
    let file = VaultFile {
        header,
        ciphertext: B64.encode(ciphertext),
    };
    serde_json::to_vec_pretty(&file).map_err(|_| StorageError::Unlock)
}

pub fn create(path: &Path, password: &str) -> Result<SessionKey, StorageError> {
    create_with_params(path, password, KdfParams::DEFAULT)
}
pub(crate) fn create_with_params(
    path: &Path,
    password: &str,
    params: KdfParams,
) -> Result<SessionKey, StorageError> {
    let salt = crypto::random_bytes::<SALT_LEN>();
    let key = crypto::derive_key(password.as_bytes(), &salt, &params)
        .map_err(|_| StorageError::Unlock)?;
    let session = SessionKey { key, salt, params };
    let bytes = encrypt_vault(&Vault::default(), &session)?;

    write_atomically(path, &bytes, false)?;
    Ok(session)
}
pub fn unlock(path: &Path, password: &str) -> Result<SessionKey, StorageError> {
    let file = read_file(path)?;
    let salt = decode::<SALT_LEN>(&file.header.salt)?;
    let params = file.header.kdf;
    let key = crypto::derive_key(password.as_bytes(), &salt, &params)
        .map_err(|_| StorageError::Unlock)?;
    decrypt_vault(&file, &key)?;
    #[cfg(unix)]
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(SessionKey { key, salt, params })
}

pub fn save(path: &Path, vault: &Vault, session: &SessionKey) -> Result<(), StorageError> {
    let bytes = encrypt_vault(vault, session)?;
    // read_file refuses anything over the limit, so writing it would lock the user out of their vault
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(StorageError::TooLarge);
    }
    write_atomically(path, &bytes, true)
}
pub fn load(path: &Path, session: &SessionKey) -> Result<Vault, StorageError> {
    decrypt_vault(&read_file(path)?, &session.key)
}
// writes a synced temp file and swaps it in
fn write_atomically(path: &Path, bytes: &[u8], overwrite: bool) -> Result<(), StorageError> {
    // same folder as the target, so the final rename never crosses filesystems
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;

    if overwrite {
        tmp.persist(path).map_err(|e| e.error)?;
    } else {
        // fails if anything already exists at path
        tmp.persist_noclobber(path).map_err(|e| e.error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::{DataDir, UserFile, Username};
    use crate::vault::access::AccessCheck;
    use crate::vault::crypto::KdfParams;
    use crate::vault::models::{Credential, Vault};
    use std::fs;
    use std::path::{Path, PathBuf};

    const PW: &str = "correct horse battery";

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

    fn new_user(data: &DataDir, name: &str) -> Session {
        create_user_with_params(data, &user(name), PW, KdfParams::TEST).unwrap()
    }

    fn vault_path(data: &DataDir, name: &str) -> PathBuf {
        data.user_file(&user(name), UserFile::Vault)
    }

    fn vault_with_github() -> Vault {
        let mut vault = Vault::default();
        vault
            .add(Credential {
                service: "github".to_string(),
                username: "alice".to_string(),
                password: "hunter2".to_string(),
            })
            .unwrap();
        vault
    }

    fn read_json(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    // rewrites the vault in place, so it keeps its 0600 mode and only the content changes
    fn tamper(path: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
        let mut json = read_json(path);
        edit(&mut json);
        fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    }

    fn flip_first_ciphertext_byte(json: &mut serde_json::Value) {
        let mut bytes = B64.decode(json["ciphertext"].as_str().unwrap()).unwrap();
        bytes[0] ^= 0x01;
        json["ciphertext"] = B64.encode(bytes).into();
    }

    // creates alice, closes her session, applies the edit and checks unlock refuses the result
    fn assert_tamper_is_refused(edit: impl FnOnce(&mut serde_json::Value)) {
        let (_dir, data) = data_dir();
        drop(new_user(&data, "alice"));
        let path = vault_path(&data, "alice");
        tamper(&path, edit);
        assert_unlock_fails_and_file_untouched(&data, "alice");
    }

    fn assert_unlock_fails_and_file_untouched(data: &DataDir, name: &str) {
        let path = vault_path(data, name);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            unlock(data, &user(name), PW),
            Err(StorageError::Unlock)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    fn file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn access_denied(result: Result<impl Sized, StorageError>) -> Option<AccessCheck> {
        match result {
            Err(StorageError::AccessDenied(check)) => Some(check),
            _ => None,
        }
    }

    // --- create and unlock ---

    // a brand new vault unlocks and has nothing in it
    #[test]
    fn create_then_unlock_gives_empty_vault() {
        let (_dir, data) = data_dir();
        drop(new_user(&data, "alice"));

        let session = unlock(&data, &user("alice"), PW).unwrap();

        assert!(load(&session).unwrap().is_empty());
        assert_eq!(session.user().as_str(), "alice");
    }

    // what we save is exactly what we get back after unlocking again
    #[test]
    fn save_then_load_round_trips() {
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");
        save(&session, &vault_with_github()).unwrap();
        drop(session);

        let reopened = unlock(&data, &user("alice"), PW).unwrap();

        assert_eq!(load(&reopened).unwrap(), vault_with_github());
    }

    // wrong password is rejected and the file stays as it was
    #[test]
    fn wrong_password_fails_and_file_untouched() {
        let (_dir, data) = data_dir();
        drop(new_user(&data, "alice"));
        let path = vault_path(&data, "alice");
        let before = fs::read(&path).unwrap();

        assert!(matches!(
            unlock(&data, &user("alice"), "wrong password"),
            Err(StorageError::Unlock)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    // spaces are part of the password and are never trimmed
    #[test]
    fn password_spaces_are_kept() {
        let (_dir, data) = data_dir();
        drop(
            create_user_with_params(&data, &user("alice"), " pässwörd ü ", KdfParams::TEST)
                .unwrap(),
        );

        assert!(matches!(
            unlock(&data, &user("alice"), "pässwörd ü"),
            Err(StorageError::Unlock)
        ));
        assert!(unlock(&data, &user("alice"), " pässwörd ü ").is_ok());
    }

    // "ä" typed on a mac keyboard can arrive as "a" + a combining mark; both must open the vault
    #[test]
    fn composed_and_decomposed_passwords_are_the_same() {
        let (_dir, data) = data_dir();
        let composed = "p\u{e4}ssw\u{f6}rd";
        let decomposed = "pa\u{308}sswo\u{308}rd";
        assert_ne!(composed, decomposed);
        drop(create_user_with_params(&data, &user("alice"), composed, KdfParams::TEST).unwrap());

        assert!(unlock(&data, &user("alice"), decomposed).is_ok());
    }

    #[test]
    fn normalize_password_is_nfkc() {
        assert_eq!(&*crypto::normalize_password("pa\u{308}ss"), "p\u{e4}ss");
        // nfkc also folds compatibility forms, like the "ﬁ" ligature
        assert_eq!(&*crypto::normalize_password("\u{fb01}x"), "fix");
    }

    // an unknown user gives the same error kind a missing vault always gave, and nothing is created
    #[test]
    fn unlock_unknown_user_is_not_found_and_creates_nothing() {
        let (dir, data) = data_dir();

        assert!(matches!(
            unlock(&data, &user("nobody"), PW),
            Err(StorageError::NotFound)
        ));
        assert!(file_names(&dir.path().join("securevault/users")).is_empty());
    }

    // creating a user never overwrites one that already exists
    #[test]
    fn create_existing_user_is_refused() {
        let (_dir, data) = data_dir();
        drop(new_user(&data, "alice"));

        let result =
            create_user_with_params(&data, &user("alice"), "another password", KdfParams::TEST);

        assert!(matches!(result, Err(StorageError::UserExists)));
        assert!(unlock(&data, &user("alice"), PW).is_ok());
    }

    // the user folder is private and the vault is owner-only from the first moment
    #[cfg(unix)]
    #[test]
    fn create_user_makes_owner_only_layout() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = data_dir();
        let _session = new_user(&data, "alice");
        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;

        assert_eq!(mode(data.user_dir(&user("alice"))), 0o700);
        assert_eq!(mode(vault_path(&data, "alice")), 0o600);
        assert_eq!(mode(data.user_file(&user("alice"), UserFile::Lock)), 0o600);
    }

    // a session is bound to one user: load and save take no path, so alice can't touch bob's vault
    #[test]
    fn session_cannot_reach_another_user() {
        let (_dir, data) = data_dir();
        let alice = new_user(&data, "alice");
        let bob = new_user(&data, "bob");

        save(&alice, &vault_with_github()).unwrap();

        assert!(load(&bob).unwrap().is_empty());
        assert_eq!(load(&alice).unwrap(), vault_with_github());
    }

    // two sessions for one user would overwrite each other's changes
    #[test]
    fn second_session_is_refused_until_first_drops() {
        let (_dir, data) = data_dir();
        let first = new_user(&data, "alice");

        assert!(matches!(
            unlock(&data, &user("alice"), PW),
            Err(StorageError::AlreadyOpen)
        ));

        drop(first);
        assert!(unlock(&data, &user("alice"), PW).is_ok());
    }

    // --- access checks ---

    // a vault others can read is refused and left as it is, not quietly fixed
    #[cfg(unix)]
    #[test]
    fn group_readable_vault_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");
        let path = vault_path(&data, "alice");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(access_denied(load(&session)), Some(AccessCheck::Mode));
        assert_eq!(
            access_denied(save(&session, &vault_with_github())),
            Some(AccessCheck::Mode)
        );
        drop(session);
        assert_eq!(
            access_denied(unlock(&data, &user("alice"), PW)),
            Some(AccessCheck::Mode)
        );
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    // a user folder others can enter is refused too
    #[cfg(unix)]
    #[test]
    fn group_readable_user_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = data_dir();
        drop(new_user(&data, "alice"));
        let folder = data.user_dir(&user("alice"));
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o750)).unwrap();

        assert_eq!(
            access_denied(unlock(&data, &user("alice"), PW)),
            Some(AccessCheck::Mode)
        );
    }

    // a symlink in place of the vault or the user folder could point anywhere; nothing is
    // read through it or written through it
    #[cfg(unix)]
    #[test]
    fn symlinked_vault_or_user_dir_is_refused() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (dir, data) = data_dir();

        // the vault replaced by a link to some other file
        let session = new_user(&data, "alice");
        let path = vault_path(&data, "alice");
        let victim = dir.path().join("victim.txt");
        fs::write(&victim, "victim data").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&victim, &path).unwrap();

        assert_eq!(
            access_denied(save(&session, &vault_with_github())),
            Some(AccessCheck::Symlink)
        );
        assert_eq!(access_denied(load(&session)), Some(AccessCheck::Symlink));
        drop(session);
        assert_eq!(
            access_denied(unlock(&data, &user("alice"), PW)),
            Some(AccessCheck::Symlink)
        );
        assert_eq!(fs::read_to_string(&victim).unwrap(), "victim data");

        // bob's folder replaced by a link to alice's
        drop(new_user(&data, "bob"));
        let bob_dir = data.user_dir(&user("bob"));
        fs::remove_dir_all(&bob_dir).unwrap();
        symlink(data.user_dir(&user("alice")), &bob_dir).unwrap();

        assert_eq!(
            access_denied(unlock(&data, &user("bob"), PW)),
            Some(AccessCheck::Symlink)
        );
    }

    // opening a fifo blocks until a writer shows up, so the type check has to come first
    #[cfg(unix)]
    #[test]
    fn named_pipe_at_vault_path_fails_fast() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (dir, data) = data_dir();
        drop(new_user(&data, "alice"));
        let path = vault_path(&data, "alice");
        fs::remove_file(&path).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());

        let (tx, rx) = mpsc::channel();
        let base = dir.path().join("securevault");
        std::thread::spawn(move || {
            let data = DataDir::at(base);
            let _ = tx.send(unlock(&data, &user("alice"), PW).is_err());
        });

        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(failed) => assert!(failed, "unlock of a fifo must fail"),
            Err(_) => {
                // release the blocked reader so the thread doesn't hang around
                let _ = fs::OpenOptions::new().write(true).open(&path);
                panic!("unlock blocked on a named pipe");
            }
        }
    }

    // --- file contents ---

    // nothing readable from the vault ends up in the file
    #[test]
    fn file_contains_no_plaintext() {
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");
        save(&session, &vault_with_github()).unwrap();

        let contents = fs::read_to_string(vault_path(&data, "alice")).unwrap();

        for secret in ["github", "hunter2"] {
            assert!(!contents.contains(secret), "file leaks {secret:?}");
        }
    }

    // every save uses a new nonce, reusing one would break the encryption
    #[test]
    fn nonce_and_ciphertext_change_on_every_save() {
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");
        let path = vault_path(&data, "alice");

        save(&session, &vault_with_github()).unwrap();
        let first = read_json(&path);
        save(&session, &vault_with_github()).unwrap();
        let second = read_json(&path);

        assert_ne!(first["header"]["nonce"], second["header"]["nonce"]);
        assert_ne!(first["ciphertext"], second["ciphertext"]);
    }

    // a file written by this version is marked as version 2
    #[test]
    fn new_vault_is_version_2() {
        let (_dir, data) = data_dir();
        drop(new_user(&data, "alice"));

        assert_eq!(
            read_json(&vault_path(&data, "alice"))["header"]["version"],
            2
        );
    }

    // --- tampering and malformed files ---

    #[test]
    fn tampered_ciphertext_fails() {
        assert_tamper_is_refused(flip_first_ciphertext_byte);
    }

    #[test]
    fn tampered_salt_fails() {
        assert_tamper_is_refused(|json| {
            let salt = B64
                .decode(json["header"]["salt"].as_str().unwrap())
                .unwrap();
            let other: Vec<u8> = salt.iter().map(|b| b ^ 0xFF).collect();
            json["header"]["salt"] = B64.encode(other).into();
        });
    }

    #[test]
    fn tampered_nonce_fails() {
        assert_tamper_is_refused(|json| {
            let nonce = B64
                .decode(json["header"]["nonce"].as_str().unwrap())
                .unwrap();
            let other: Vec<u8> = nonce.iter().map(|b| b ^ 0xFF).collect();
            json["header"]["nonce"] = B64.encode(other).into();
        });
    }

    #[test]
    fn tampered_kdf_param_fails() {
        assert_tamper_is_refused(|json| json["header"]["kdf"]["t_cost"] = 2.into());
    }

    // huge argon2 settings are rejected before they can freeze the app
    #[test]
    fn out_of_bounds_kdf_param_fails() {
        assert_tamper_is_refused(|json| json["header"]["kdf"]["m_cost"] = 4_000_000_000u64.into());
    }

    // version 1 hashed the password without normalising it, so its key can't be rebuilt; refused
    #[test]
    fn version_1_file_is_refused() {
        assert_tamper_is_refused(|json| json["header"]["version"] = 1.into());
    }

    #[test]
    fn unknown_version_is_refused() {
        assert_tamper_is_refused(|json| json["header"]["version"] = 3.into());
    }

    #[test]
    fn unknown_field_in_header_fails() {
        assert_tamper_is_refused(|json| json["header"]["extra"] = "x".into());
    }

    #[test]
    fn unknown_top_level_field_fails() {
        assert_tamper_is_refused(|json| json["extra"] = "x".into());
    }

    // garbage instead of base64 gives an error, not a crash
    #[test]
    fn bad_base64_fails() {
        assert_tamper_is_refused(|json| json["ciphertext"] = "!!!not base64".into());
    }

    #[test]
    fn wrong_salt_length_fails() {
        assert_tamper_is_refused(|json| json["header"]["salt"] = B64.encode([1u8; 15]).into());
    }

    #[test]
    fn unlock_short_ciphertext_fails() {
        assert_tamper_is_refused(|json| json["ciphertext"] = B64.encode([1u8; 4]).into());
    }

    #[test]
    fn unlock_empty_file_fails() {
        let (_dir, data) = data_dir();
        drop(new_user(&data, "alice"));
        fs::write(vault_path(&data, "alice"), "").unwrap();

        assert_unlock_fails_and_file_untouched(&data, "alice");
    }

    // an old unencrypted vault from slice 1 is not accepted
    #[test]
    fn unlock_plaintext_slice1_file_fails() {
        let (_dir, data) = data_dir();
        drop(new_user(&data, "alice"));
        fs::write(
            vault_path(&data, "alice"),
            r#"{"credentials":[{"username":"a","password":"b","service":"c"}]}"#,
        )
        .unwrap();

        assert_unlock_fails_and_file_untouched(&data, "alice");
    }

    // a giant file is rejected instead of being read whole into memory
    #[test]
    fn oversized_file_fails() {
        let (_dir, data) = data_dir();
        drop(new_user(&data, "alice"));
        let path = vault_path(&data, "alice");
        let mut bytes = fs::read(&path).unwrap();
        bytes.resize(MAX_FILE_BYTES as usize + 1, b' ');
        fs::write(&path, &bytes).unwrap();

        assert_unlock_fails_and_file_untouched(&data, "alice");
    }

    // tampering is caught even after the vault was already unlocked
    #[test]
    fn load_with_session_after_tamper_fails() {
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");

        tamper(&vault_path(&data, "alice"), flip_first_ciphertext_byte);

        assert!(matches!(load(&session), Err(StorageError::Unlock)));
    }

    // only changing the header (not the key or nonce) must still break decryption, proves the header is aad
    #[test]
    fn header_is_bound_as_aad() {
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");
        let mut file: VaultFile =
            serde_json::from_slice(&fs::read(vault_path(&data, "alice")).unwrap()).unwrap();
        assert!(decrypt_vault(&file, session.key()).is_ok());

        file.header.version = 1;

        assert!(matches!(
            decrypt_vault(&file, session.key()),
            Err(StorageError::Unlock)
        ));
    }

    // a vault written by this version must keep opening in every later version
    #[test]
    fn golden_v2_vault_still_opens() {
        let (_dir, data) = data_dir();
        drop(new_user(&data, "alice"));
        fs::write(vault_path(&data, "alice"), GOLDEN_V2).unwrap();

        let session = unlock(&data, &user("alice"), GOLDEN_PASSWORD).unwrap();

        assert_eq!(load(&session).unwrap(), vault_with_github());
    }

    const GOLDEN_V2: &str = include_str!("../../tests/fixtures/vault_v2.json");
    const GOLDEN_PASSWORD: &str = "golden pässwörd";

    // --- saving ---

    // a save that fails halfway must leave the old vault exactly as it was
    #[cfg(unix)]
    #[test]
    fn failed_save_keeps_old_vault() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");
        let folder = data.user_dir(&user("alice"));
        let before = fs::read(vault_path(&data, "alice")).unwrap();
        // read-only folder: the access checks pass (no group or other bits) but writing fails
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o500)).unwrap();

        let result = save(&session, &vault_with_github());

        fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(result, Err(StorageError::Io(_))));
        assert_eq!(fs::read(vault_path(&data, "alice")).unwrap(), before);
        assert!(load(&session).unwrap().is_empty());
    }

    // saving never leaves a temp file lying around
    #[test]
    fn no_tmp_file_left_after_save() {
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");

        save(&session, &vault_with_github()).unwrap();

        assert_eq!(
            file_names(&data.user_dir(&user("alice"))),
            vec!["lock", "vault.json"]
        );
    }

    // fields are capped (a password is at most 1024 bytes), so a big vault needs many entries.
    fn vault_with_entries(count: usize) -> Vault {
        let mut vault = Vault::default();
        for i in 0..count {
            vault
                .add(Credential {
                    service: format!("service{i}"),
                    username: "alice".to_string(),
                    password: "a".repeat(1024),
                })
                .unwrap();
        }
        vault
    }

    // a vault too big to read back must not be written, or the next unlock would lock the user out
    #[test]
    fn save_refuses_vault_over_size_limit() {
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");
        let before = fs::read(vault_path(&data, "alice")).unwrap();

        let result = save(&session, &vault_with_entries(8000)); // about 11.5 MB on disk

        assert!(matches!(result, Err(StorageError::TooLarge)));
        assert_eq!(fs::read(vault_path(&data, "alice")).unwrap(), before);
        assert!(load(&session).is_ok());
    }

    // the save limit is not stricter than the read limit: what fits is saved and loads back
    #[test]
    fn anything_saved_can_be_loaded() {
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");
        let vault = vault_with_entries(6500); // about 9.3 MB on disk

        save(&session, &vault).unwrap();

        assert!(fs::metadata(vault_path(&data, "alice")).unwrap().len() <= MAX_FILE_BYTES);
        assert_eq!(load(&session).unwrap(), vault);
    }

    // saves racing on the same vault must not trip over each other's temp file
    #[test]
    fn concurrent_saves_all_succeed_and_vault_stays_readable() {
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");
        let vault = vault_with_github();

        let errors: usize = std::thread::scope(|s| {
            let workers: Vec<_> = (0..2)
                .map(|_| s.spawn(|| (0..50).filter(|_| save(&session, &vault).is_err()).count()))
                .collect();
            workers.into_iter().map(|w| w.join().unwrap()).sum()
        });

        assert_eq!(errors, 0);
        assert_eq!(load(&session).unwrap(), vault_with_github());
        assert_eq!(
            file_names(&data.user_dir(&user("alice"))),
            vec!["lock", "vault.json"]
        );
    }

    // --- review fixes: half-created users ---

    // what a crash (ctrl-c, kill) during create_user leaves today: the user folder, maybe a
    // temp file from the interrupted write, and no vault
    fn leave_half_created_user(data: &DataDir, name: &str, with_tmp: bool) -> PathBuf {
        let folder = data.user_dir(&user(name));
        fs::create_dir(&folder).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
        }
        if with_tmp {
            let tmp = folder.join(".tmpAbC123");
            fs::write(&tmp, b"partial write").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        folder
    }

    // a folder with no vault is not a user: it must not burn password attempts
    #[test]
    fn half_created_user_is_unknown_not_a_wrong_password() {
        let (_dir, data) = data_dir();
        leave_half_created_user(&data, "alice", false);

        assert!(matches!(
            unlock(&data, &user("alice"), PW),
            Err(StorageError::NotFound)
        ));
    }

    // a crash during create must not take the name away for good
    #[test]
    fn half_created_user_can_be_created_again() {
        for with_tmp in [false, true] {
            let (_dir, data) = data_dir();
            leave_half_created_user(&data, "alice", with_tmp);

            let session = create_user_with_params(&data, &user("alice"), PW, KdfParams::TEST)
                .unwrap_or_else(|e| panic!("with_tmp={with_tmp}: {e:?}"));
            save(&session, &vault_with_github()).unwrap();
            drop(session);

            let session = unlock(&data, &user("alice"), PW).unwrap();
            assert_eq!(load(&session).unwrap(), vault_with_github());
        }
    }

    // reusing a leftover folder is only safe if it is ours and private; one someone else could
    // have prepared is refused and left alone, not fixed or deleted
    #[cfg(unix)]
    #[test]
    fn half_created_folder_with_loose_mode_is_not_reused() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, data) = data_dir();
        let folder = leave_half_created_user(&data, "alice", false);
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();

        let result = create_user_with_params(&data, &user("alice"), PW, KdfParams::TEST);

        assert_eq!(access_denied(result), Some(AccessCheck::Mode));
        let mode = fs::metadata(&folder).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    // --- review fixes: the data folder and users/ are checked too ---

    fn set_mode(path: &Path, mode: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    // whoever can write the data folder or users/ can swap the user folder itself, so checking
    // only the user folder protects nothing
    #[cfg(unix)]
    #[test]
    fn loose_parent_folders_are_refused() {
        for parent in ["", "users"] {
            for mode in [0o755, 0o777] {
                let (dir, data) = data_dir();
                let folder = dir.path().join("securevault").join(parent);
                let session = new_user(&data, "alice");
                set_mode(&folder, mode);
                let case = format!("{parent:?} {mode:o}");

                assert_eq!(access_denied(load(&session)), Some(AccessCheck::Mode), "{case}");
                assert_eq!(
                    access_denied(save(&session, &vault_with_github())),
                    Some(AccessCheck::Mode),
                    "{case}"
                );
                drop(session);
                assert_eq!(
                    access_denied(unlock(&data, &user("alice"), PW)),
                    Some(AccessCheck::Mode),
                    "{case}"
                );
                assert_eq!(
                    access_denied(create_user_with_params(
                        &data,
                        &user("bob"),
                        PW,
                        KdfParams::TEST
                    )),
                    Some(AccessCheck::Mode),
                    "{case}"
                );
                // refused, not quietly fixed
                let now = fs::metadata(&folder).unwrap();
                assert_eq!(
                    std::os::unix::fs::PermissionsExt::mode(&now.permissions()) & 0o777,
                    mode,
                    "{case}"
                );
                set_mode(&folder, 0o700); // so the temp dir can be cleaned up
            }
        }
    }

    // a symlinked data folder or users/ could be repointed at any time
    #[cfg(unix)]
    #[test]
    fn symlinked_parent_folders_are_refused() {
        use std::os::unix::fs::symlink;

        // the data folder itself is a link
        let (dir, real) = data_dir();
        drop(new_user(&real, "alice"));
        let link = dir.path().join("link");
        symlink(dir.path().join("securevault"), &link).unwrap();
        let linked = DataDir::at(link);
        assert_eq!(
            access_denied(unlock(&linked, &user("alice"), PW)),
            Some(AccessCheck::Symlink)
        );
        assert_eq!(
            access_denied(create_user_with_params(
                &linked,
                &user("bob"),
                PW,
                KdfParams::TEST
            )),
            Some(AccessCheck::Symlink)
        );
        assert!(!real.user_dir(&user("bob")).exists());

        // users/ swapped for a link while a session is open
        let (dir, data) = data_dir();
        let session = new_user(&data, "alice");
        let users = dir.path().join("securevault/users");
        let moved = dir.path().join("securevault/users-real");
        fs::rename(&users, &moved).unwrap();
        symlink(&moved, &users).unwrap();
        assert_eq!(access_denied(load(&session)), Some(AccessCheck::Symlink));
        assert_eq!(
            access_denied(save(&session, &vault_with_github())),
            Some(AccessCheck::Symlink)
        );
        drop(session);
        assert_eq!(
            access_denied(unlock(&data, &user("alice"), PW)),
            Some(AccessCheck::Symlink)
        );
    }

    // logging in before anyone has created a user is an unknown user, and it creates nothing
    #[test]
    fn unlock_with_no_data_folder_is_not_found_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let data = DataDir::at(dir.path().join("securevault"));

        assert!(matches!(
            unlock(&data, &user("alice"), PW),
            Err(StorageError::NotFound)
        ));
        assert!(!dir.path().join("securevault").exists());
    }

    // --- review fixes: the lock file ---

    // the lock file is opened with create, so a planted link would make the app create or open
    // a file of the attacker's choosing
    #[cfg(unix)]
    #[test]
    fn symlinked_lock_file_is_refused() {
        use std::os::unix::fs::symlink;
        for target_exists in [false, true] {
            let (dir, data) = data_dir();
            drop(new_user(&data, "alice"));
            let lock = data.user_file(&user("alice"), UserFile::Lock);
            let target = dir.path().join("planted");
            if target_exists {
                fs::write(&target, "keep me").unwrap();
                set_mode(&target, 0o600);
            }
            fs::remove_file(&lock).unwrap();
            symlink(&target, &lock).unwrap();

            assert_eq!(
                access_denied(unlock(&data, &user("alice"), PW)),
                Some(AccessCheck::Symlink),
                "target_exists={target_exists}"
            );
            if target_exists {
                assert_eq!(fs::read_to_string(&target).unwrap(), "keep me");
            } else {
                assert!(!target.exists(), "lock symlink was followed");
            }
        }
    }

    // --- review fixes: NotFound is only "unknown user" during unlock ---

    // a folder that disappears mid-session is a storage problem, not a wrong password
    #[test]
    fn vanished_user_folder_mid_session_is_a_storage_error() {
        let (_dir, data) = data_dir();
        let session = new_user(&data, "alice");
        let folder = data.user_dir(&user("alice"));
        fs::remove_dir_all(&folder).unwrap();

        assert!(matches!(load(&session), Err(StorageError::Io(_))));
        assert!(matches!(
            save(&session, &vault_with_github()),
            Err(StorageError::Io(_))
        ));
        assert!(!folder.exists(), "save recreated the folder");
    }

    // creating a user never shows the unlock message, whatever goes wrong on disk
    // (/proc refuses new folders with "not found", the case the regression run hit)
    #[cfg(target_os = "linux")]
    #[test]
    fn create_user_never_reports_an_unlock_error() {
        let data = DataDir::at(PathBuf::from("/proc/self/securevault-test/x"));

        let error = create_user_with_params(&data, &user("alice"), PW, KdfParams::TEST).err();

        assert!(matches!(error, Some(StorageError::Io(_))), "{error:?}");
    }

    // --- messages ---

    // what reaches the screen is one of the fixed messages: no path, no os error text
    #[test]
    fn display_messages_leak_no_internals() {
        let allowed = [
            "Could not access vault storage",
            "Couldn't unlock vault",
            "Access denied",
            "Vault is too large to save",
            "Username is not available",
            "This vault is already open in another session",
        ];
        let errors = [
            StorageError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "/home/alice/secret: os error 13",
            )),
            StorageError::NotFound,
            StorageError::Unlock,
            StorageError::AccessDenied(AccessCheck::Owner),
            StorageError::TooLarge,
            StorageError::UserExists,
            StorageError::AlreadyOpen,
        ];
        for error in errors {
            let message = error.to_string();
            assert!(allowed.contains(&message.as_str()), "{message:?}");
        }
    }
}
