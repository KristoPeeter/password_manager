use std ::{fs, fmt, io, path::Path};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::crypto::{self, KdfParams, Key, SALT_LEN, NONCE_LEN};

use super::models::Vault;
use std::io::Write;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const VERSION: u32 = 1;

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    NotFound,
    Unlock,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "Could not access vault file: {}", e),
            StorageError::NotFound => write!(f, "No vault found"),
            StorageError::Unlock => write!(f, "Couldn't unlock vault"),
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
    let bytes = fs::read(path)?;
    let file: VaultFile = serde_json::from_slice(&bytes).map_err(|_| StorageError::Unlock)?; // checked before any argon2 call so attack cant allocate memory
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

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)?.write_all(&bytes)?;

    Ok(session)
}
pub fn unlock(path: &Path, password: &str) -> Result<SessionKey, StorageError> {
    let file = read_file(path)?;
    let salt = decode::<SALT_LEN>(&file.header.salt)?;
    let params = file.header.kdf;
    let key = crypto::derive_key(password.as_bytes(), &salt, &params).map_err(|_| StorageError::Unlock)?;
    decrypt_vault(&file, &key)?;
    Ok(SessionKey { key, salt, params })
}

pub fn save(path: &Path, vault: &Vault, session: &SessionKey) -> Result<(), StorageError> {
    fs::write(path, encrypt_vault(vault, session)?)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
pub fn load(path: &Path, session: &SessionKey) -> Result<Vault, StorageError> {
    decrypt_vault(&read_file(path)?, &session.key)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::KdfParams;
    use crate::vault::models::{Credential, Vault};
    use std::fs;
    use std::path::{Path, PathBuf};

    const PW: &str = "correct horse battery";

    fn new_vault(dir: &tempfile::TempDir) -> (PathBuf, SessionKey) {
        let path = dir.path().join("vault.json");
        let session = create_with_params(&path, PW, KdfParams::TEST).unwrap();
        (path, session)
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

    fn assert_unlock_fails_and_file_untouched(path: &Path) {
        let before = fs::read(path).unwrap();
        assert!(matches!(unlock(path, PW), Err(StorageError::Unlock)));
        assert_eq!(fs::read(path).unwrap(), before);
    }

    // a brand new vault unlocks and has nothing in it
    #[test]
    fn create_then_unlock_gives_empty_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        let session = unlock(&path, PW).unwrap();

        assert!(load(&path, &session).unwrap().is_empty());
    }

    // what we save is exactly what we get back after unlocking again
    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let (path, session) = new_vault(&dir);
        save(&path, &vault_with_github(), &session).unwrap();

        let reopened = unlock(&path, PW).unwrap();

        assert_eq!(load(&path, &reopened).unwrap(), vault_with_github());
    }

    // wrong password is rejected and the file stays as it was
    #[test]
    fn wrong_password_fails_and_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);
        let before = fs::read(&path).unwrap();

        assert!(matches!(
            unlock(&path, "wrong password"),
            Err(StorageError::Unlock)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    // password is used as typed, spaces and special letters are not trimmed or changed
    #[test]
    fn unicode_and_spaces_password_round_trips_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        create_with_params(&path, " pässwörd ü ", KdfParams::TEST).unwrap();

        assert!(unlock(&path, " pässwörd ü ").is_ok());
        assert!(matches!(
            unlock(&path, "pässwörd ü"),
            Err(StorageError::Unlock)
        ));
    }

    // no file means no vault, so the ui knows to create one
    #[test]
    fn unlock_missing_file_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        assert!(matches!(unlock(&path, PW), Err(StorageError::NotFound)));
    }

    // creating a vault never overwrites one that already exists
    #[test]
    fn create_refuses_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        let result = create_with_params(&path, "another password", KdfParams::TEST);

        assert!(
            matches!(result, Err(StorageError::Io(ref e)) if e.kind() == io::ErrorKind::AlreadyExists)
        );
        assert!(unlock(&path, PW).is_ok());
    }

    // nothing readable from the vault ends up in the file
    #[test]
    fn file_contains_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let (path, session) = new_vault(&dir);
        save(&path, &vault_with_github(), &session).unwrap();

        let contents = fs::read_to_string(&path).unwrap();

        for secret in ["github", "alice", "hunter2"] {
            assert!(!contents.contains(secret), "file leaks {secret:?}");
        }
    }

    // every save uses a new nonce, reusing one would break the encryption
    #[test]
    fn nonce_and_ciphertext_change_on_every_save() {
        let dir = tempfile::tempdir().unwrap();
        let (path, session) = new_vault(&dir);

        save(&path, &vault_with_github(), &session).unwrap();
        let first = read_json(&path);
        save(&path, &vault_with_github(), &session).unwrap();
        let second = read_json(&path);

        assert_ne!(first["header"]["nonce"], second["header"]["nonce"]);
        assert_ne!(first["ciphertext"], second["ciphertext"]);
    }

    // changing the encrypted data is detected
    #[test]
    fn tampered_ciphertext_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        tamper(&path, flip_first_ciphertext_byte);

        assert_unlock_fails_and_file_untouched(&path);
    }

    // changing the salt is detected
    #[test]
    fn tampered_salt_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        tamper(&path, |json| {
            let salt = B64.decode(json["header"]["salt"].as_str().unwrap()).unwrap();
            let other: Vec<u8> = salt.iter().map(|b| b ^ 0xFF).collect();
            json["header"]["salt"] = B64.encode(other).into();
        });

        assert_unlock_fails_and_file_untouched(&path);
    }

    // changing the nonce is detected
    #[test]
    fn tampered_nonce_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        tamper(&path, |json| {
            let nonce = B64.decode(json["header"]["nonce"].as_str().unwrap()).unwrap();
            let other: Vec<u8> = nonce.iter().map(|b| b ^ 0xFF).collect();
            json["header"]["nonce"] = B64.encode(other).into();
        });

        assert_unlock_fails_and_file_untouched(&path);
    }

    // changing the argon2 settings is detected
    #[test]
    fn tampered_kdf_param_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        tamper(&path, |json| json["header"]["kdf"]["t_cost"] = 2.into());

        assert_unlock_fails_and_file_untouched(&path);
    }

    // huge argon2 settings are rejected before they can freeze the app
    #[test]
    fn out_of_bounds_kdf_param_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        tamper(&path, |json| {
            json["header"]["kdf"]["m_cost"] = 4_000_000_000u64.into()
        });

        assert_unlock_fails_and_file_untouched(&path);
    }

    // a file version we don't know is rejected
    #[test]
    fn wrong_version_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        tamper(&path, |json| json["header"]["version"] = 2.into());

        assert_unlock_fails_and_file_untouched(&path);
    }

    // extra fields in the file are rejected
    #[test]
    fn unknown_field_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        tamper(&path, |json| json["header"]["extra"] = "x".into());
        assert_unlock_fails_and_file_untouched(&path);

        tamper(&path, |json| {
            json["header"].as_object_mut().unwrap().remove("extra");
            json["extra"] = "x".into();
        });
        assert_unlock_fails_and_file_untouched(&path);
    }

    // garbage instead of base64 gives an error, not a crash
    #[test]
    fn bad_base64_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        tamper(&path, |json| json["ciphertext"] = "!!!not base64".into());

        assert_unlock_fails_and_file_untouched(&path);
    }

    // a salt of the wrong size gives an error, not a crash
    #[test]
    fn wrong_salt_length_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        tamper(&path, |json| json["header"]["salt"] = B64.encode([1u8; 15]).into());

        assert_unlock_fails_and_file_untouched(&path);
    }

    // ciphertext too short to be real gives an error, not a crash
    #[test]
    fn unlock_short_ciphertext_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        tamper(&path, |json| json["ciphertext"] = B64.encode([1u8; 4]).into());

        assert_unlock_fails_and_file_untouched(&path);
    }

    // an empty file gives an error, not a crash
    #[test]
    fn unlock_empty_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        fs::write(&path, "").unwrap();

        assert_unlock_fails_and_file_untouched(&path);
    }

    // an old unencrypted vault from slice 1 is not accepted
    #[test]
    fn unlock_plaintext_slice1_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        fs::write(
            &path,
            r#"{"credentials":[{"username":"a","password":"b","service":"c"}]}"#,
        )
        .unwrap();

        assert_unlock_fails_and_file_untouched(&path);
    }

    // tampering is caught even after the vault was already unlocked
    #[test]
    fn load_with_session_after_tamper_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);
        let session = unlock(&path, PW).unwrap();

        tamper(&path, flip_first_ciphertext_byte);

        assert!(matches!(load(&path, &session), Err(StorageError::Unlock)));
    }

    // only the owner can read or write a new vault file
    #[cfg(unix)]
    #[test]
    fn create_sets_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = new_vault(&dir);

        let mode = fs::metadata(&path).unwrap().permissions().mode();

        assert_eq!(mode & 0o777, 0o600);
    }

    // saving puts the owner-only permissions back if someone loosened them
    #[cfg(unix)]
    #[test]
    fn save_restores_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (path, session) = new_vault(&dir);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        save(&path, &vault_with_github(), &session).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
