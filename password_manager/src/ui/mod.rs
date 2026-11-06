mod clipboard;

use std::{fmt, io, path::Path, process::ExitCode};

use inquire::{
    Confirm, InquireError, Password, PasswordDisplayMode, Select, Text, required,
    validator::Validation,
};
use zeroize::Zeroizing;

use clipboard::{CLEAR_AFTER, ClipboardManager};

use crate::vault::{
    models::{Credential, Vault, VaultError},
    storage::{self, SessionKey, StorageError},
};

const VAULT_PATH: &str = "vault.json";

#[derive(Clone, Copy)]
enum MenuAction {
    Add,
    List,
    Copy,
    Delete,
    Exit,
}

impl fmt::Display for MenuAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            MenuAction::Add => "Add credential",
            MenuAction::List => "List credentials",
            MenuAction::Copy => "Copy password",
            MenuAction::Delete => "Delete credential",
            MenuAction::Exit => "Exit",
        };
        write!(f, "{}", label)
    }
}

const MENU: [MenuAction; 5] = [
    MenuAction::Add,
    MenuAction::List,
    MenuAction::Copy,
    MenuAction::Delete,
    MenuAction::Exit,
];

enum ActionError {
    Cancelled,
    Prompt(InquireError),
    Vault(VaultError),
    Storage(StorageError),
    Io(io::Error),
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionError::Cancelled => write!(f, "Cancelled"),
            ActionError::Prompt(e) => write!(f, "Prompt failed: {}", e),
            ActionError::Vault(e) => write!(f, "{}", e),
            ActionError::Storage(e) => write!(f, "{}", e),
            ActionError::Io(e) => write!(f, "Terminal error: {}", e),
        }
    }
}

impl From<InquireError> for ActionError {
    fn from(e: InquireError) -> Self {
        match e {
            InquireError::OperationCanceled | InquireError::OperationInterrupted => {
                ActionError::Cancelled
            }
            other => ActionError::Prompt(other),
        }
    }
}

impl From<VaultError> for ActionError {
    fn from(e: VaultError) -> Self {
        ActionError::Vault(e)
    }
}

impl From<StorageError> for ActionError {
    fn from(e: StorageError) -> Self {
        ActionError::Storage(e)
    }
}

impl From<io::Error> for ActionError {
    fn from(e: io::Error) -> Self {
        ActionError::Io(e)
    }
}

const UNLOCK_ATTEMPTS: usize = 3;

pub fn run() -> ExitCode {
    let path = Path::new(VAULT_PATH);

    // try_exists, not exists: a permission error must not look like "no vault yet"
    let session = match path.try_exists() {
        Ok(false) => match create_vault(path) {
            Some(session) => session,
            None => return ExitCode::SUCCESS,
        },
        Ok(true) => match unlock_vault(path) {
            Ok(Some(session)) => session,
            Ok(None) => return ExitCode::SUCCESS,
            Err(()) => return ExitCode::FAILURE,
        },
        Err(e) => {
            eprintln!("Could not access vault file: {e}");
            return ExitCode::FAILURE;
        }
    };

    // None when there is no usable clipboard, copy then reports it instead of printing the password
    let clipboard = clipboard::system().ok();
    let exit = |code: ExitCode| {
        if let Some(clipboard) = &clipboard {
            clipboard.clear_if_unchanged();
        }
        code
    };

    loop {
        let mut vault = match storage::load(path, &session) {
            Ok(vault) => vault,
            Err(e) => {
                eprintln!("Error: {}", e);
                return exit(ExitCode::FAILURE);
            }
        };

        let Ok(action) = Select::new("What would you like to do?", MENU.to_vec()).prompt() else {
            return exit(ExitCode::SUCCESS);
        };

        let result = match action {
            MenuAction::Add => add(&mut vault, path, &session),
            MenuAction::List => {
                list(&vault);
                Ok(())
            }
            MenuAction::Copy => copy(&vault, clipboard.as_ref()),
            MenuAction::Delete => delete(&mut vault, path, &session),
            MenuAction::Exit => return exit(ExitCode::SUCCESS),
        };

        match result {
            Ok(()) => {}
            Err(ActionError::Cancelled) => println!("Cancelled."),
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}

fn create_vault(path: &Path) -> Option<SessionKey> {
    println!("No vault found — create one.");
    let password = Password::new("New master password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_custom_confirmation_message("Confirm master password:")
        .with_custom_confirmation_error_message("Passwords do not match")
        .with_validator(|input: &str| {
            Ok(match validate_master_password(input) {
                Ok(()) => Validation::Valid,
                Err(message) => Validation::Invalid(message.into()),
            })
        })
        .prompt()
        .ok()
        .map(Zeroizing::new)?;

    match storage::create(path, &password) {
        Ok(session) => Some(session),
        Err(e) => {
            eprintln!("Error: {}", e);
            None
        }
    }
}

// Ok(None) means the user cancelled, Err(()) means give up and exit with failure
fn unlock_vault(path: &Path) -> Result<Option<SessionKey>, ()> {
    for _ in 0..UNLOCK_ATTEMPTS {
        let Ok(password) = Password::new("Master password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt()
            .map(Zeroizing::new)
        else {
            return Ok(None);
        };

        match storage::unlock(path, &password) {
            Ok(session) => return Ok(Some(session)),
            Err(StorageError::Unlock) => eprintln!("Couldn't unlock vault"),
            Err(e) => {
                eprintln!("{}", e);
                return Err(());
            }
        }
    }
    Err(())
}

fn add(vault: &mut Vault, path: &Path, session: &SessionKey) -> Result<(), ActionError> {
    let service = Text::new("Service:")
        .with_validator(required!("Service is required"))
        .prompt()?;
    if vault.get(&service).is_some() {
        return Err(VaultError::DuplicateService.into());
    }
    let username = Text::new("Username:").prompt()?;
    let password = Password::new("Password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_custom_confirmation_message("Confirm password:")
        .with_custom_confirmation_error_message("Passwords do not match")
        .prompt()?;

    vault.add(Credential {
        service,
        username,
        password,
    })?;
    storage::save(path, vault, session)?;
    println!("Saved.");
    Ok(())
}

fn list(vault: &Vault) {
    if vault.is_empty() {
        println!("Vault is empty.");
        return;
    }
    vault
        .credentials()
        .iter()
        .for_each(|c| println!("{} — {}", c.service, c.username));
}

// never falls back to printing, a password must not end up in the terminal or its scrollback
fn copy(
    vault: &Vault,
    clipboard: Option<&ClipboardManager<arboard::Clipboard>>,
) -> Result<(), ActionError> {
    let Some(service) = select_service(vault)? else {
        return Ok(());
    };
    let credential = vault.get(&service).ok_or(VaultError::NotFound)?;

    match clipboard.map(|clipboard| clipboard.copy(&credential.password)) {
        Some(Ok(())) => println!(
            "Copied password for '{}' — clipboard clears in {}s.",
            service,
            CLEAR_AFTER.as_secs()
        ),
        _ => eprintln!("Clipboard unavailable"),
    }
    Ok(())
}

fn delete(vault: &mut Vault, path: &Path, session: &SessionKey) -> Result<(), ActionError> {
    let Some(service) = select_service(vault)? else {
        return Ok(());
    };
    let confirmed = Confirm::new(&format!("Delete '{}'?", service))
        .with_default(false)
        .prompt()?;
    if !confirmed {
        return Err(ActionError::Cancelled);
    }

    vault.remove(&service)?;
    storage::save(path, vault, session)?;
    println!("Deleted.");
    Ok(())
}

fn select_service(vault: &Vault) -> Result<Option<String>, ActionError> {
    if vault.is_empty() {
        println!("Vault is empty.");
        return Ok(None);
    }
    let service = Select::new("Service:", vault.services()).prompt()?;
    Ok(Some(service.to_string()))
}
// min counts characters (what the user sees), max counts bytes (what argon2 has to hash)
fn validate_master_password(password: &str) -> Result<(), &'static str> {
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

    // 7 characters is too weak to protect the vault
    #[test]
    fn rejects_seven_characters() {
        assert_eq!(validate_master_password("1234567"), TOO_SHORT);
    }

    // 8 characters is the minimum we accept
    #[test]
    fn accepts_eight_characters() {
        assert_eq!(validate_master_password("12345678"), Ok(()));
    }

    // length is counted in characters, so umlauts don't count double
    #[test]
    fn counts_characters_not_bytes() {
        assert_eq!(validate_master_password("ääääääää"), Ok(()));
        assert_eq!(validate_master_password("äääääää"), TOO_SHORT);
    }

    // an absurdly long password is refused so argon2 never hashes megabytes of input
    #[test]
    fn rejects_over_1024_bytes() {
        assert_eq!(validate_master_password(&"a".repeat(1025)), TOO_LONG);
        assert_eq!(validate_master_password(&"a".repeat(1024)), Ok(()));
    }

    // spaces are part of the password, nothing is trimmed
    #[test]
    fn does_not_trim() {
        assert_eq!(validate_master_password("       a"), Ok(()));
    }

    // the menu offers copy, never a way to show the password on screen
    #[test]
    fn menu_copies_instead_of_showing_passwords() {
        let labels: Vec<String> = MENU.iter().map(|action| action.to_string()).collect();
        assert_eq!(
            labels,
            [
                "Add credential",
                "List credentials",
                "Copy password",
                "Delete credential",
                "Exit"
            ]
        );
    }
}
