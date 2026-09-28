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
}
