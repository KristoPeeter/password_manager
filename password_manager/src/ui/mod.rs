use std::{
    fmt,
    io::{self, Write},
    path::Path,
};

use inquire::{Confirm, InquireError, Password, PasswordDisplayMode, Select, Text, required};

use crate::vault::{
    models::{Credential, Vault, VaultError},
    storage::{self, SessionKey, StorageError},
};

const VAULT_PATH: &str = "vault.json";

#[derive(Clone, Copy)]
enum MenuAction {
    Add,
    List,
    Get,
    Delete,
    Exit,
}

impl fmt::Display for MenuAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            MenuAction::Add => "Add credential",
            MenuAction::List => "List credentials",
            MenuAction::Get => "Show password",
            MenuAction::Delete => "Delete credential",
            MenuAction::Exit => "Exit",
        };
        write!(f, "{}", label)
    }
}

const MENU: [MenuAction; 5] = [
    MenuAction::Add,
    MenuAction::List,
    MenuAction::Get,
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

pub fn run() {
    let path = Path::new(VAULT_PATH);
    let Ok(password) = Password::new("Master password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()
    else {
        return;
    };
    let opened = if path.exists() {
        storage::unlock(path, &password)
    } else {
        storage::create(path, &password)
    };
    let session = match opened {
        Ok(session) => session,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    loop {
        let mut vault = match storage::load(path, &session) {
            Ok(vault) => vault,
            Err(e) => {
                eprintln!("Error: {}", e);
                return;
            }
        };

        let Ok(action) = Select::new("What would you like to do?", MENU.to_vec()).prompt() else {
            return;
        };

        let result = match action {
            MenuAction::Add => add(&mut vault, path, &session),
            MenuAction::List => {
                list(&vault);
                Ok(())
            }
            MenuAction::Get => get(&vault),
            // MenuAction::Update => update(&mut vault, path, &session),
            MenuAction::Delete => delete(&mut vault, path, &session),
            MenuAction::Exit => return,
        };

        match result {
            Ok(()) => {}
            Err(ActionError::Cancelled) => println!("Cancelled."),
            Err(e) => eprintln!("Error: {}", e),
        }
    }
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

fn get(vault: &Vault) -> Result<(), ActionError> {
    let Some(service) = select_service(vault)? else {
        return Ok(());
    };
    let credential = vault.get(&service).ok_or(VaultError::NotFound)?;

    println!("Username: {}", credential.username);
    println!("Password: {}", credential.password);
    println!("Press Enter to clear the screen...");
    io::stdin().read_line(&mut String::new())?;

    // this is here to clear the terminal
    print!("\x1B[2J\x1B[3J\x1B[H");
    io::stdout().flush()?;
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
