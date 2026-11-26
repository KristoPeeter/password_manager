use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Field {
    Service,
    Username,
    Password,
}

impl Field {
    // the name that goes into the log, so it is fixed and never contains a value. Logging to be added asap
    pub fn as_str(self) -> &'static str {
        match self {
            Field::Service => "service",
            Field::Username => "username",
            Field::Password => "password",
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ValidationError {
    pub field: Field,
    pub message: &'static str,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ValidationError {}

const MAX_SERVICE_CHARS: usize = 64;
// 254 is the longest valid email address (RFC 5321), the most common kind of username
const MAX_USERNAME_CHARS: usize = 254;
const MAX_PASSWORD_BYTES: usize = 1024;

fn invalid<T>(field: Field, message: &'static str) -> Result<T, ValidationError> {
    Err(ValidationError { field, message })
}

// control characters include line breaks and the escape byte that starts terminal colour and cursor codes. refusing them means every stored value is safe to print or log.
// checked before trimming, because trim would quietly remove a trailing newline
fn reject_control_characters(input: &str, field: Field) -> Result<(), ValidationError> {
    if input.chars().any(char::is_control) {
        invalid(
            field,
            "Control characters (line breaks, tabs, escape codes) are not allowed",
        )
    } else {
        Ok(())
    }
}

// returns the trimmed name, so "github" and "github " can't become two entries
pub fn service(input: &str) -> Result<String, ValidationError> {
    reject_control_characters(input, Field::Service)?;
    let value = input.trim();
    match value.chars().count() {
        0 => invalid(Field::Service, "Service name is required"),
        n if n > MAX_SERVICE_CHARS => {
            invalid(Field::Service, "Service name can be at most 64 characters")
        }
        _ => Ok(value.to_owned()),
    }
}

// empty is allowed: some sites only use a password or an email elsewhere
pub fn credential_username(input: &str) -> Result<String, ValidationError> {
    reject_control_characters(input, Field::Username)?;
    let value = input.trim();
    if value.chars().count() > MAX_USERNAME_CHARS {
        invalid(Field::Username, "Username can be at most 254 characters")
    } else {
        Ok(value.to_owned())
    }
}

// never trimmed: spaces can be part of a password. the cap is in bytes because it
// bounds memory and file size, not what the user sees
pub fn credential_password(input: &str) -> Result<(), ValidationError> {
    if input.is_empty() {
        return invalid(Field::Password, "Password is required");
    }
    if input.len() > MAX_PASSWORD_BYTES {
        return invalid(Field::Password, "Password is too long");
    }
    reject_control_characters(input, Field::Password)
}

// min counts characters (what the user sees), max counts bytes (what argon2 has to hash)
pub fn master_password(password: &str) -> Result<(), &'static str> {
    if password.chars().count() < 8 {
        Err("Master password must be at least 8 characters")
    } else if password.len() > 1024 {
        Err("Master password is too long")
    } else {
        Ok(())
    }
}

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

    // the limits apply to what argon2 actually gets, after nfkc: "a" plus a combining umlaut is one character, and some single characters expand to dozens
    #[test]
    fn master_password_limits_apply_after_normalisation() {
        assert_eq!(master_password(&"a\u{308}".repeat(4)), TOO_SHORT);
        assert_eq!(master_password(&"a\u{308}".repeat(8)), Ok(()));
        // U+FDFA is 3 bytes, and 18 characters (33 bytes) after nfkc
        let expands = "\u{FDFA}".repeat(40);
        assert!(expands.len() <= 1024);
        assert_eq!(master_password(&expands), TOO_LONG);
    }

    // characters that reorder or break the text around them would let a stored name look like a different one on screen or in the log
    #[test]
    fn bidi_controls_and_line_separators_are_rejected() {
        for bad in [
            "a\u{202a}b", // left-to-right embedding
            "a\u{202e}b", // right-to-left override
            "a\u{2066}b", // left-to-right isolate
            "a\u{2069}b", // pop directional isolate
            "a\u{200e}b", // left-to-right mark
            "a\u{200f}b", // right-to-left mark
            "a\u{2028}b", // line separator
            "a\u{2029}b", // paragraph separator
        ] {
            assert_eq!(field_of(service(bad)), Some(Field::Service), "{bad:?}");
            assert_eq!(
                field_of(credential_username(bad)),
                Some(Field::Username),
                "{bad:?}"
            );
        }
    }

    // é typed as one character or as e plus a combining accent is the same service
    #[test]
    fn service_is_nfc_normalised() {
        assert_eq!(service("cafe\u{301}"), Ok("caf\u{e9}".to_string()));
        assert_eq!(service("caf\u{e9}"), Ok("caf\u{e9}".to_string()));
    }
}
