#[cfg(test)]
mod tests {
    use super::*;

    const TOO_SHORT: Result<(), &str> = Err("Master password must be at least 8 characters");
    const TOO_LONG: Result<(), &str> = Err("Master password is too long");

    fn field_of<T>(result: Result<T, ValidationError>) -> Option<Field> {
        result.err().map(|e| e.field)
    }

    // 8 characters is the minimum, 7 is too weak to protect the vault
    #[test]
    fn master_password_minimum_is_eight() {
        assert_eq!(master_password("1234567"), TOO_SHORT);
        assert_eq!(master_password("12345678"), Ok(()));
    }

    // length is counted in characters, so umlauts don't count double
    #[test]
    fn counts_characters_not_bytes() {
        assert_eq!(master_password("ääääääää"), Ok(()));
        assert_eq!(master_password("äääääää"), TOO_SHORT);
    }

    // an absurdly long password is refused so argon2 never hashes megabytes of input
    #[test]
    fn rejects_over_1024_bytes() {
        assert_eq!(master_password(&"a".repeat(1025)), TOO_LONG);
        assert_eq!(master_password(&"a".repeat(1024)), Ok(()));
    }

    // spaces are part of the password, nothing is trimmed
    #[test]
    fn does_not_trim() {
        assert_eq!(master_password("       a"), Ok(()));
    }

    // --- credential fields ---

    // trimmed so "github" and "github " can't be two entries; the limit applies after trimming
    #[test]
    fn service_limits_and_trimming() {
        assert!(service("a").is_ok());
        assert_eq!(service("  github  "), Ok("github".to_string()));
        let padded = format!("  {}  ", "a".repeat(64));
        assert_eq!(service(&padded), Ok("a".repeat(64)));
        for bad in ["", "   ", &"a".repeat(65)] {
            assert_eq!(field_of(service(bad)), Some(Field::Service), "{bad:?}");
        }
    }

    // some sites have no username, so empty is allowed
    #[test]
    fn username_limits_and_trimming() {
        assert_eq!(credential_username(""), Ok(String::new()));
        assert_eq!(credential_username(" alice "), Ok("alice".to_string()));
        assert!(credential_username(&"a".repeat(254)).is_ok());
        assert_eq!(
            field_of(credential_username(&"a".repeat(255))),
            Some(Field::Username)
        );
    }

    // bytes, not characters: the cap is a memory and size guard, like the master password's
    #[test]
    fn password_limits_are_bytes() {
        assert!(credential_password(&"a".repeat(1024)).is_ok());
        assert!(credential_password(&"ä".repeat(512)).is_ok());
        for bad in [String::new(), "a".repeat(1025), "ä".repeat(513)] {
            assert_eq!(
                field_of(credential_password(&bad)),
                Some(Field::Password),
                "{} bytes",
                bad.len()
            );
        }
    }

    // line breaks and escape codes would let a stored value rewrite the terminal or forge log lines
    #[test]
    fn control_characters_are_rejected() {
        for bad in [
            "a\nb",
            "a\tb",
            "a\0b",
            "\x1b[31mred",
            "a\u{7f}b",
            "a\u{85}b",
        ] {
            assert_eq!(field_of(service(bad)), Some(Field::Service), "{bad:?}");
            assert_eq!(
                field_of(credential_username(bad)),
                Some(Field::Username),
                "{bad:?}"
            );
            assert_eq!(
                field_of(credential_password(bad)),
                Some(Field::Password),
                "{bad:?}"
            );
        }
    }

    // trimming must not hide a control character at the edge
    #[test]
    fn trailing_newline_is_rejected_not_trimmed() {
        assert_eq!(field_of(service("github\n")), Some(Field::Service));
        assert_eq!(
            field_of(credential_username("alice\n")),
            Some(Field::Username)
        );
    }

    // the limit is what the user sees, so umlauts don't count double
    #[test]
    fn multibyte_characters_count_as_one() {
        assert!(service(&"ä".repeat(64)).is_ok());
        assert!(service(&"ä".repeat(65)).is_err());
        assert!(credential_username(&"ä".repeat(254)).is_ok());
    }
}
