use std ::{fs, fmt, io, path::Path};
use super::models::Vault;

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Parse(serde_json::Error),
}
impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "I/O error: {}", e),
            StorageError::Parse(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        StorageError::Io(e)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::Parse(e)
    }
}

pub fn load(path: &Path) -> Result<Vault, StorageError> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(serde_json::from_str(&contents)?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vault::default()),
        Err(e) => Err(e.into()),
    }
}

pub fn save(path: &Path, vault: &Vault) -> Result<(), StorageError> {
    let json = serde_json::to_string_pretty(vault)?;
    fs::write(path, json)?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::models::{Credential, Vault};
    use std::fs;

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

    #[test]
    fn test_save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let vault = vault_with_github();

        save(&path, &vault).unwrap();

        assert_eq!(load(&path).unwrap(), vault);
    }

    #[test]
    fn test_load_missing_file_returns_empty_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        let vault = load(&path).unwrap();

        assert!(vault.is_empty());
    }

    #[test]
    fn test_load_malformed_file_returns_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        fs::write(&path, "{not json").unwrap();

        let result = load(&path);

        assert!(matches!(result, Err(StorageError::Parse(_))));
    }

    #[test]
    fn test_load_malformed_file_leaves_it_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        fs::write(&path, "{not json").unwrap();

        let _ = load(&path);

        assert_eq!(fs::read_to_string(&path).unwrap(), "{not json");
    }
}
