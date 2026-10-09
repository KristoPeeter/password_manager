use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
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
}
#[derive(Debug, PartialEq)]
pub enum VaultError {
    NotFound,
    DuplicateService,
}

impl Vault {
    pub fn get(&self, service: &str) -> Option<&Credential> {
        self.credentials.iter().find(|c| c.service == service)
    }
    pub fn add(&mut self, credential: Credential) -> Result<(), VaultError> {
        if self.get(&credential.service).is_some() {
            return Err(VaultError::DuplicateService);
        }
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
}


#[cfg(test)]
mod tests {
    use super::*;

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
        let result= vault.remove("service2");
        assert_eq!(result, Ok(()));
        assert_eq!(vault.get("service2"), None);
        assert_eq!(vault.get("service1").is_some(), true);
        assert_eq!(vault.get("service3").is_some(), true);

    }
    #[test]
    fn test_delete_error(){
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
    #[test]
    fn test_is_empty() {
        let mut vault = Vault::default();
        assert!(vault.is_empty());

        vault.add(credential("service1")).unwrap();
        assert!(!vault.is_empty());

        vault.remove("service1").unwrap();
        assert!(vault.is_empty());
    }
}
