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
