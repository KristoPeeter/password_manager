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
        vault.remove("service2");
        assert_eq!(vault.get("service2"), None);
    }
    #[test]
    fn test_delete_error(){
        let mut vault = vault_multiple(&["service1", "service2", "service3"]);
        let result_from_failure = vault.remove("service4");
        assert_eq!(result_from_failure, Err(VaultError::NotFound));
    }
}
