#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [7; SALT_LEN];
    const NONCE: [u8; NONCE_LEN] = [9; NONCE_LEN];

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
        assert!(!KdfParams { m_cost: 1_048_577, ..p }.is_within_bounds());
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
