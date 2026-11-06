use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub type Key = Zeroizing<[u8; KEY_LEN]>;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub const DEFAULT: Self = Self {
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
    };

    #[cfg(test)]
    pub const TEST: Self = Self {
        m_cost: 8_192,
        t_cost: 1,
        p_cost: 1,
    };

    // because params are read from the untrusted external file we cap them before Argon2 allocates memory.
    pub fn is_within_bounds(&self) -> bool {
        (8_192..=1_048_576).contains(&self.m_cost)
            && (1..=10).contains(&self.t_cost)
            && (1..=4).contains(&self.p_cost)
    }
}

#[derive(Debug, PartialEq)]
pub struct CryptoError;

pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Key, CryptoError> {
    if !params.is_within_bounds() {
        return Err(CryptoError);
    }
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError)?;
    let mut key: Key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params)
        .hash_password_into(password, salt, &mut *key)
        .map_err(|_| CryptoError)?;
    Ok(key)
}

pub fn encrypt(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| CryptoError)?;
    cipher
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError)
}

pub fn decrypt(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| CryptoError)?;
    cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::fill(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [7; SALT_LEN];
    const NONCE: [u8; NONCE_LEN] = [9; NONCE_LEN]; //number used once

    fn key(password: &str) -> Key {
        derive_key(password.as_bytes(), &SALT, &KdfParams::TEST).unwrap()
    }

    #[test]
    fn derive_key_is_deterministic() {
        assert_eq!(*key("correct horse"), *key("correct horse"));
    }

    #[test]
    fn derive_key_differs_by_password_and_salt() {
        assert_ne!(*key("a-password"), *key("b-password"));
        let other_salt = derive_key(b"a-password", &[8; SALT_LEN], &KdfParams::TEST).unwrap();
        assert_ne!(*key("a-password"), *other_salt);
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let k = key("pw");
        let ciphertext = encrypt(&k, &NONCE, b"aad", b"secret").unwrap();
        assert_eq!(
            decrypt(&k, &NONCE, b"aad", &ciphertext).unwrap().as_slice(),
            b"secret"
        );
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let ciphertext = encrypt(&key("right"), &NONCE, b"aad", b"secret").unwrap();
        assert_eq!(
            decrypt(&key("wrong"), &NONCE, b"aad", &ciphertext),
            Err(CryptoError)
        );
    }

    #[test]
    fn decrypt_with_different_aad_fails() {
        let k = key("pw");
        let ciphertext = encrypt(&k, &NONCE, b"aad", b"secret").unwrap();
        assert_eq!(decrypt(&k, &NONCE, b"AAD", &ciphertext), Err(CryptoError));
    }

    #[test]
    fn decrypt_with_flipped_byte_fails() {
        let k = key("pw");
        let mut ciphertext = encrypt(&k, &NONCE, b"aad", b"secret").unwrap();
        ciphertext[0] ^= 0x01;
        assert_eq!(decrypt(&k, &NONCE, b"aad", &ciphertext), Err(CryptoError));
    }

    #[test]
    fn default_and_test_params_are_within_bounds() {
        assert!(KdfParams::DEFAULT.is_within_bounds());
        assert!(KdfParams::TEST.is_within_bounds());
    }

    #[test]
    fn out_of_bounds_params_are_rejected() {
        let p = KdfParams::DEFAULT;
        assert!(!KdfParams { m_cost: 8191, ..p }.is_within_bounds());
        assert!(
            !KdfParams {
                m_cost: 1_048_577,
                ..p
            }
            .is_within_bounds()
        );
        assert!(!KdfParams { t_cost: 0, ..p }.is_within_bounds());
        assert!(!KdfParams { t_cost: 11, ..p }.is_within_bounds());
        assert!(!KdfParams { p_cost: 0, ..p }.is_within_bounds());
        assert!(!KdfParams { p_cost: 5, ..p }.is_within_bounds());
    }

    #[test]
    fn random_bytes_are_not_repeated() {
        assert_ne!(random_bytes::<NONCE_LEN>(), random_bytes::<NONCE_LEN>());
    }
}
