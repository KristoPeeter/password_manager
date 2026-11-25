mod clipboard;

use std::{fmt, io, process::ExitCode};

use inquire::{
    Confirm, InquireError, Password, PasswordDisplayMode, Select, Text, required,
    validator::Validation,
};
use zeroize::Zeroizing;

use clipboard::{CLEAR_AFTER, ClipboardManager};

use crate::paths::{DataDir, UserFile, Username};
use crate::vault::{
    models::{Credential, Vault, VaultError},
    storage::{self, Session, StorageError},
    validation,
};

// temporary bridge until the login screen exists (task 7): one fixed user, so the app keeps
// working on the new per-user storage. task 11 replaces this
const BRIDGE_USER: &str = "default";

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
    let data = match DataDir::resolve() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let Ok(user) = Username::parse(BRIDGE_USER) else {
        return ExitCode::FAILURE;
    };

    // try_exists, not exists: a permission error must not look like "no vault yet"
    let session = match data.user_file(&user, UserFile::Vault).try_exists() {
        Ok(false) => match create_vault(&data, &user) {
            Ok(Some(session)) => session,
            Ok(None) => return ExitCode::SUCCESS,
            Err(()) => return ExitCode::FAILURE,
        },
        Ok(true) => match unlock_vault(&data, &user) {
            Ok(Some(session)) => session,
            Ok(None) => return ExitCode::SUCCESS,
            Err(()) => return ExitCode::FAILURE,
        },
        Err(_) => {
            eprintln!("{}", StorageError::Io(io::ErrorKind::Other.into()));
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
        let mut vault = match storage::load(&session) {
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
            MenuAction::Add => add(&mut vault, &session),
            MenuAction::List => {
                list(&vault);
                Ok(())
            }
            MenuAction::Copy => copy(&vault, clipboard.as_ref()),
            MenuAction::Delete => delete(&mut vault, &session),
            MenuAction::Exit => return exit(ExitCode::SUCCESS),
        };

        match result {
            Ok(()) => {}
            Err(ActionError::Cancelled) => println!("Cancelled."),
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}

// Ok(None) means the user cancelled, Err(()) means creating failed and the app exits with failure
fn create_vault(data: &DataDir, user: &Username) -> Result<Option<Session>, ()> {
    println!("No vault found — create one.");
    let password = Password::new("New master password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_custom_confirmation_message("Confirm master password:")
        .with_custom_confirmation_error_message("Passwords do not match")
        .with_validator(|input: &str| {
            Ok(match validation::master_password(input) {
                Ok(()) => Validation::Valid,
                Err(message) => Validation::Invalid(message.into()),
            })
        })
        .prompt()
        .ok()
        .map(Zeroizing::new);
    let Some(password) = password else {
        return Ok(None);
    };

    match storage::create_user(data, user, &password) {
        Ok(session) => Ok(Some(session)),
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(())
        }
    }
}

// Ok(None) means the user cancelled, Err(()) means give up and exit with failure
fn unlock_vault(data: &DataDir, user: &Username) -> Result<Option<Session>, ()> {
    for _ in 0..UNLOCK_ATTEMPTS {
        let Ok(password) = Password::new("Master password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt()
            .map(Zeroizing::new)
        else {
            return Ok(None);
        };

        match storage::unlock(data, user, &password) {
            Ok(session) => return Ok(Some(session)),
            Err(e @ (StorageError::Unlock | StorageError::NotFound)) => eprintln!("{e}"),
            Err(e) => {
                eprintln!("{}", e);
                return Err(());
            }
        }
    }
    Err(())
}

fn add(vault: &mut Vault, session: &Session) -> Result<(), ActionError> {
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
    storage::save(session, vault)?;
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

fn delete(vault: &mut Vault, session: &Session) -> Result<(), ActionError> {
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
    storage::save(session, vault)?;
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
#[cfg(test)]
mod tests {
    use super::*;

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
