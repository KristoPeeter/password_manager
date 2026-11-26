use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::validation::{self, ValidationError};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Credential {
    pub username: String,
    pub password: String,
    pub service: String,
}
#[derive(Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Vault {
    credentials: Vec<Credential>,
    // default: vaults saved before the log seal existed read as never sealed
    #[serde(default)]
    log_sealed: bool,
}
#[derive(Debug, PartialEq)]
pub enum VaultError {
    NotFound,
    DuplicateService,
    Invalid(ValidationError),
}
impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::NotFound => write!(f, "Credential not found"),
            VaultError::DuplicateService => write!(f, "Credential already exists"),
            VaultError::Invalid(e) => write!(f, "{e}"),
        }
    }
}

impl From<ValidationError> for VaultError {
    fn from(e: ValidationError) -> Self {
        VaultError::Invalid(e)
    }
}

impl Vault {
    // set after the first log seal, so a deleted log.seal can't pass for a first login
    pub fn log_sealed(&self) -> bool {
        self.log_sealed
    }

    pub fn mark_log_sealed(&mut self) {
        self.log_sealed = true;
    }

    pub fn get(&self, service: &str) -> Option<&Credential> {
        self.credentials.iter().find(|c| c.service == service)
    }
    // validates here as well as in the prompts, so no caller can store an unchecked field
    pub fn add(&mut self, mut credential: Credential) -> Result<(), VaultError> {
        let service = validation::service(&credential.service)?;
        let username = validation::credential_username(&credential.username)?;
        validation::credential_password(&credential.password)?;
        if self.get(&service).is_some() {
            return Err(VaultError::DuplicateService);
        }
        credential.service = service;
        credential.username = username;
        self.credentials.push(credential);
        Ok(())
    }
    pub fn remove(&mut self, service: &str) -> Result<(), VaultError> {
        let pos = self
            .credentials
            .iter()
            .position(|c| c.service == service)
            .ok_or(VaultError::NotFound)?;
        self.credentials.remove(pos);
        Ok(())
    }
    fn get_mut(&mut self, service: &str) -> Result<&mut Credential, VaultError> {
        self.credentials
            .iter_mut()
            .find(|c| c.service == service)
            .ok_or(VaultError::NotFound)
    }

    // not called by the ui until the update menu entry is added (task 11)
    pub fn update_username(&mut self, service: &str, new: &str) -> Result<(), VaultError> {
        let credential = self.get_mut(service)?;
        let username = validation::credential_username(new)?;
        credential.username.zeroize();
        credential.username = username;
        Ok(())
    }

    // takes Zeroizing so the caller's copy of the new password is wiped too
    pub fn update_password(
        &mut self,
        service: &str,
        mut new: Zeroizing<String>,
    ) -> Result<(), VaultError> {
        let credential = self.get_mut(service)?;
        validation::credential_password(&new)?;
        // wipe the old password before it is dropped, then move the new one in without copying it
        credential.password.zeroize();
        credential.password = std::mem::take(&mut *new);
        Ok(())
    }

    #[cfg(test)]
    pub fn services(&self) -> Vec<&str> {
        self.credentials
            .iter()
            .map(|c| c.service.as_str())
            .collect()
    }

    pub fn credentials(&self) -> &[Credential] {
        &self.credentials
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::validation::Field;

    fn credential(service: &str) -> Credential {
        Credential {
            service: service.to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
        }
    }
    fn vault_multiple(services: &[&str]) -> Vault {
        let mut vault = Vault::default();
        for &service in services {
            vault.add(credential(service)).unwrap();
        }
        vault
    }
    #[test]
    fn test_credential() {
        let mut vault = Vault::default();

        vault.add(credential("service1")).unwrap();

        assert_eq!(vault.get("service1"), Some(&credential("service1")));
    }

    #[test]
    fn test_duplicate_service() {
        let mut vault = Vault::default();
        vault.add(credential("service1")).unwrap();
        let result_from_failure = vault.add(credential("service1"));
        assert_eq!(result_from_failure, Err(VaultError::DuplicateService));
    }
    #[test]
    fn test_delete_entry() {
        let mut vault = vault_multiple(&["service1", "service2", "service3"]);
        let result = vault.remove("service2");
        assert_eq!(result, Ok(()));
        assert_eq!(vault.get("service2"), None);
        assert!(vault.get("service1").is_some());
        assert!(vault.get("service3").is_some());
    }
    #[test]
    fn test_delete_error() {
        let mut vault = vault_multiple(&["service1", "service2", "service3"]);
        let result_from_failure = vault.remove("service4");
        assert_eq!(result_from_failure, Err(VaultError::NotFound));
    }
    #[test]
    fn test_services_in_insertion_order() {
        let vault = vault_multiple(&["service2", "service1", "service3"]);
        assert_eq!(vault.services(), vec!["service2", "service1", "service3"]);
    }
    #[test]
    fn test_services_empty_vault() {
        let vault = Vault::default();
        assert!(vault.services().is_empty());
    }
    #[test]
    fn test_credentials_returns_all_entries() {
        let vault = vault_multiple(&["service1", "service2"]);
        assert_eq!(
            vault.credentials(),
            &[credential("service1"), credential("service2")]
        );
    }
    // wiping a credential leaves nothing of the secret behind in its strings
    #[test]
    fn credential_zeroize_empties_every_field() {
        use zeroize::Zeroize;
        let mut c = credential("service1");

        c.zeroize();

        assert!(c.service.is_empty());
        assert!(c.username.is_empty());
        assert!(c.password.is_empty());
    }

    // compile-time check: dropping these types wipes them, nobody has to remember to call zeroize
    #[test]
    fn secret_types_are_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Credential>();
        assert_zeroize_on_drop::<crate::vault::crypto::Key>();
    }

    #[test]
    fn test_is_empty() {
        let mut vault = Vault::default();
        assert!(vault.is_empty());

        vault.add(credential("service1")).unwrap();
        assert!(!vault.is_empty());

        vault.remove("service1").unwrap();
        assert!(vault.is_empty());
    }

    // --- validation and update (task 3) ---

    fn credential_with(service: &str, username: &str, password: &str) -> Credential {
        Credential {
            service: service.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    fn invalid_field(result: Result<(), VaultError>) -> Option<Field> {
        match result {
            Err(VaultError::Invalid(e)) => Some(e.field),
            _ => None,
        }
    }

    // add is the last gate before the vault, so it checks every field itself
    #[test]
    fn add_rejects_invalid_fields() {
        let mut vault = vault_multiple(&["service1"]);
        let cases = [
            (
                credential_with(&"a".repeat(65), "user", "pass"),
                Field::Service,
            ),
            (
                credential_with("ok", &"a".repeat(255), "pass"),
                Field::Username,
            ),
            (credential_with("ok", "user", ""), Field::Password),
            (credential_with("ok", "user", "a\nb"), Field::Password),
        ];
        for (bad, field) in cases {
            assert_eq!(invalid_field(vault.add(bad)), Some(field));
        }
        assert_eq!(vault.services(), vec!["service1"]);
    }

    // service and username are stored trimmed, the password exactly as typed
    #[test]
    fn add_stores_trimmed_service_and_username_but_not_password() {
        let mut vault = Vault::default();

        vault
            .add(credential_with("  github ", " alice ", " a "))
            .unwrap();

        let stored = vault.get("github").unwrap();
        assert_eq!(stored.username, "alice");
        assert_eq!(stored.password, " a ");
    }

    // "github " must count as the existing "github", not a second entry
    #[test]
    fn add_detects_duplicate_after_trimming() {
        let mut vault = vault_multiple(&["github"]);

        let result = vault.add(credential_with(" github ", "user", "pass"));

        assert_eq!(result, Err(VaultError::DuplicateService));
        assert_eq!(vault.services(), vec!["github"]);
    }

    #[test]
    fn update_username_changes_only_that_field() {
        let mut vault = vault_multiple(&["service1", "service2"]);

        vault.update_username("service1", " bob ").unwrap();

        assert_eq!(
            vault.get("service1"),
            Some(&credential_with("service1", "bob", "pass"))
        );
        assert_eq!(vault.get("service2"), Some(&credential("service2")));
    }

    #[test]
    fn update_password_changes_only_that_field() {
        let mut vault = vault_multiple(&["service1", "service2"]);

        vault
            .update_password("service1", Zeroizing::new(" new pass ".to_string()))
            .unwrap();

        assert_eq!(
            vault.get("service1"),
            Some(&credential_with("service1", "user", " new pass "))
        );
        assert_eq!(vault.get("service2"), Some(&credential("service2")));
    }

    #[test]
    fn update_unknown_service_is_not_found() {
        let mut vault = vault_multiple(&["service1"]);

        assert_eq!(
            vault.update_username("missing", "bob"),
            Err(VaultError::NotFound)
        );
        assert_eq!(
            vault.update_password("missing", Zeroizing::new("new".to_string())),
            Err(VaultError::NotFound)
        );
    }

    // a rejected update must leave the old value in place, not a half-written one
    #[test]
    fn update_rejects_invalid_values() {
        let mut vault = vault_multiple(&["service1"]);

        assert_eq!(
            invalid_field(vault.update_username("service1", "a\x1b[31m")),
            Some(Field::Username)
        );
        assert_eq!(
            invalid_field(vault.update_password("service1", Zeroizing::new(String::new()))),
            Some(Field::Password)
        );
        assert_eq!(vault.get("service1"), Some(&credential("service1")));
    }

    // the flag is stored in the vault, and vaults written before it existed read as unsealed
    #[test]
    fn log_sealed_flag_round_trips() {
        let mut vault = Vault::default();
        assert!(!vault.log_sealed());

        vault.mark_log_sealed();
        let json = serde_json::to_string(&vault).unwrap();
        let back: Vault = serde_json::from_str(&json).unwrap();
        assert!(back.log_sealed());

        let old: Vault = serde_json::from_str(r#"{"credentials":[]}"#).unwrap();
        assert!(!old.log_sealed());
    }

    // "é" can be typed as one character or as "e" plus an accent; both spellings are the same service
    #[test]
    fn add_detects_duplicate_after_normalisation() {
        let mut vault = vault_multiple(&["caf\u{e9}"]);

        let result = vault.add(credential_with("cafe\u{301}", "user", "pass"));

        assert_eq!(result, Err(VaultError::DuplicateService));
        assert_eq!(vault.services(), vec!["caf\u{e9}"]);
    }
}
