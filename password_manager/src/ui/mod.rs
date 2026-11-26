pub(crate) mod clipboard;

use std::{
    fmt,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use inquire::{
    Confirm, InquireError, Password, PasswordDisplayMode, Select, Text, validator::Validation,
};
use zeroize::Zeroizing;

use clipboard::{CLEAR_AFTER, ClipboardManager};

use crate::actions::{self, LoggedIn, OpError};
use crate::audit::{Event, LogCheck, Logger};
use crate::hardening;
use crate::paths::{DataDir, UserFile, Username};
use crate::vault::auth::LoginError;
use crate::vault::lockout::LockState;
use crate::vault::storage::{Session, StorageError};
use crate::vault::validation;

// the ui only prompts and prints. every vault or login operation goes through actions, which
// validates, saves and logs; no decrypted vault is ever held here

const UNLOCK_ATTEMPTS: usize = 3;
const STORAGE_UNAVAILABLE: &str = "Could not access vault storage";
const USERNAME_RULES: &str =
    "1–32 characters: a–z, 0–9, - and _, starting with a letter or a digit";

type SystemClipboard = ClipboardManager<arboard::Clipboard>;

#[derive(Clone, Copy)]
enum StartupAction {
    LogIn,
    CreateUser,
    Exit,
}

impl fmt::Display for StartupAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            StartupAction::LogIn => "Log in",
            StartupAction::CreateUser => "Create new user",
            StartupAction::Exit => "Exit",
        };
        write!(f, "{label}")
    }
}

const STARTUP: [StartupAction; 3] = [
    StartupAction::LogIn,
    StartupAction::CreateUser,
    StartupAction::Exit,
];

#[derive(Clone, Copy)]
enum MenuAction {
    Add,
    List,
    Copy,
    Update,
    Delete,
    Exit,
}

impl fmt::Display for MenuAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            MenuAction::Add => "Add credential",
            MenuAction::List => "List credentials",
            MenuAction::Copy => "Copy password",
            MenuAction::Update => "Update credential",
            MenuAction::Delete => "Delete credential",
            MenuAction::Exit => "Exit",
        };
        write!(f, "{label}")
    }
}

const MENU: [MenuAction; 6] = [
    MenuAction::Add,
    MenuAction::List,
    MenuAction::Copy,
    MenuAction::Update,
    MenuAction::Delete,
    MenuAction::Exit,
];

#[derive(Clone, Copy)]
enum UpdateField {
    Username,
    Password,
}

impl fmt::Display for UpdateField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            UpdateField::Username => "Username",
            UpdateField::Password => "Password",
        };
        write!(f, "{label}")
    }
}

// what happens after a menu-level prompt fails
#[derive(Debug, PartialEq)]
pub(crate) enum Outcome {
    Exit(u8),
}

// Esc and Ctrl-C are the user's choice (exit 0); no terminal or a broken one is a failure (exit 1)
pub(crate) fn outcome_of_prompt_error(e: &InquireError) -> Outcome {
    match e {
        InquireError::OperationCanceled | InquireError::OperationInterrupted => Outcome::Exit(0),
        _ => Outcome::Exit(1),
    }
}

fn exit_code_of(e: &InquireError) -> u8 {
    let Outcome::Exit(code) = outcome_of_prompt_error(e);
    code
}

// only the spec's fixed messages: a wrong password and an unknown user read the same
pub(crate) fn message_for_login(e: &LoginError) -> String {
    match e {
        LoginError::Locked { remaining_secs } => {
            format!("Too many failed attempts. Try again in {remaining_secs} seconds.")
        }
        LoginError::BadCredentials { .. } => "Couldn't unlock vault".to_string(),
        // fixed texts too: no os error message and no path
        LoginError::Storage(e) => e.to_string(),
    }
}

// what to tell the user about the log check at login; None when there is nothing to say
pub(crate) fn message_for_log_check(check: &LogCheck) -> Option<String> {
    match check {
        LogCheck::Tampered(_) => {
            Some("Warning: the activity log was changed outside the app".to_string())
        }
        LogCheck::Clean {
            failed_attempts_since_last_session: 0,
        } => None,
        LogCheck::Clean {
            failed_attempts_since_last_session: n,
        } => Some(format!(
            "{n} failed unlock attempts for this user since your last session"
        )),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn run() -> ExitCode {
    hardening::install_panic_hook();
    hardening::disable_core_dumps();

    let data = match DataDir::resolve() {
        Ok(data) if data.ensure().is_ok() => data,
        _ => {
            eprintln!("{STORAGE_UNAVAILABLE}");
            return ExitCode::FAILURE;
        }
    };
    let log = Logger::open(&data, now);
    if !log.is_available() {
        eprintln!("Logging unavailable");
    }
    log.log(None, Event::AppStart);

    // None when there is no usable clipboard; copy then reports it instead of printing the password
    let clipboard = clipboard::system().ok();
    if let Some(clipboard) = &clipboard {
        // best-effort: without it, closing the terminal leaves the 20 s timer as the only clear
        let _ = hardening::clear_clipboard_on_signals(clipboard);
    }

    let code = startup(&data, &log, clipboard.as_ref());

    if let Some(clipboard) = &clipboard {
        clipboard.clear_if_unchanged();
    }
    log.log(None, Event::AppExit { code });
    ExitCode::from(code)
}

// where a startup flow leads
enum Step {
    Back,
    Exit(u8),
    LoggedIn(LoggedIn),
}

fn startup(data: &DataDir, log: &Logger, clipboard: Option<&SystemClipboard>) -> u8 {
    loop {
        let choice = match Select::new("SecureVault", STARTUP.to_vec()).prompt() {
            Ok(choice) => choice,
            Err(e) => return exit_code_of(&e),
        };
        let step = match choice {
            StartupAction::LogIn => log_in(data, log),
            StartupAction::CreateUser => create_user(data, log),
            StartupAction::Exit => return 0,
        };
        match step {
            Step::Back => {}
            Step::Exit(code) => return code,
            Step::LoggedIn(logged_in) => {
                if let Some(message) = message_for_log_check(&logged_in.check) {
                    println!("{message}");
                }
                let code = main_menu(&logged_in.session, log, clipboard);
                // every way out of the menu ends the session properly
                actions::logout(log, logged_in);
                return code;
            }
        }
    }
}

fn prompt_username() -> Result<Option<Username>, InquireError> {
    let name = match Text::new("Username:").prompt() {
        Ok(name) => name,
        Err(InquireError::OperationCanceled) => return Ok(None),
        Err(e) => return Err(e),
    };
    match Username::parse(&name) {
        Ok(user) => Ok(Some(user)),
        Err(_) => {
            // counts as nothing: no lookup, no log entry, no hint about who exists
            eprintln!("Invalid username");
            Ok(None)
        }
    }
}

fn log_in(data: &DataDir, log: &Logger) -> Step {
    let user = match prompt_username() {
        Ok(Some(user)) => user,
        Ok(None) => return Step::Back,
        Err(e) => return Step::Exit(exit_code_of(&e)),
    };
    if let LockState::Locked { remaining_secs } = actions::lock_state(data, log, &user, now()) {
        eprintln!(
            "{}",
            message_for_login(&LoginError::Locked { remaining_secs })
        );
        return Step::Back;
    }

    for _ in 0..UNLOCK_ATTEMPTS {
        let password = match Password::new("Master password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt()
        {
            Ok(password) => Zeroizing::new(password),
            Err(InquireError::OperationCanceled) => return Step::Back,
            Err(e) => return Step::Exit(exit_code_of(&e)),
        };
        match actions::login(data, log, &user, &password, now()) {
            Ok(logged_in) => return Step::LoggedIn(logged_in),
            Err(e @ LoginError::BadCredentials { .. }) => eprintln!("{}", message_for_login(&e)),
            Err(e @ LoginError::Locked { .. }) => {
                eprintln!("{}", message_for_login(&e));
                return Step::Back;
            }
            // access denied, already open, storage errors: not something another try fixes
            Err(e) => {
                eprintln!("{}", message_for_login(&e));
                return Step::Exit(1);
            }
        }
    }
    Step::Exit(1)
}

fn create_user(data: &DataDir, log: &Logger) -> Step {
    let name = match Text::new("Username:")
        .with_validator(|input: &str| {
            Ok(match Username::parse(input) {
                Ok(_) => Validation::Valid,
                Err(_) => Validation::Invalid(USERNAME_RULES.into()),
            })
        })
        .prompt()
    {
        Ok(name) => name,
        Err(InquireError::OperationCanceled) => return Step::Back,
        Err(e) => return Step::Exit(exit_code_of(&e)),
    };
    let Ok(user) = Username::parse(&name) else {
        return Step::Back;
    };
    // asked before the password, so nobody types one for a name that can't be used
    if data.user_file(&user, UserFile::Vault).exists() {
        eprintln!("{}", StorageError::UserExists);
        return Step::Back;
    }

    let password = match Password::new("New master password:")
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
    {
        Ok(password) => Zeroizing::new(password),
        Err(InquireError::OperationCanceled) => return Step::Back,
        Err(e) => return Step::Exit(exit_code_of(&e)),
    };

    match actions::create_user(data, log, &user, &password) {
        Ok(logged_in) => Step::LoggedIn(logged_in),
        Err(e @ StorageError::UserExists) => {
            eprintln!("{e}");
            Step::Back
        }
        Err(e) => {
            eprintln!("{e}");
            Step::Exit(1)
        }
    }
}

// a failed action: back to the menu, or out of the app
enum ActionError {
    Cancelled,
    Prompt(InquireError),
    Op(OpError),
}

impl From<InquireError> for ActionError {
    fn from(e: InquireError) -> Self {
        match e {
            InquireError::OperationCanceled => ActionError::Cancelled,
            other => ActionError::Prompt(other),
        }
    }
}

impl From<OpError> for ActionError {
    fn from(e: OpError) -> Self {
        ActionError::Op(e)
    }
}

// the menu comes first and each action loads what it needs, so nothing decrypted waits here
fn main_menu(session: &Session, log: &Logger, clipboard: Option<&SystemClipboard>) -> u8 {
    loop {
        let action = match Select::new("What would you like to do?", MENU.to_vec()).prompt() {
            Ok(action) => action,
            Err(e) => return exit_code_of(&e),
        };
        let result = match action {
            MenuAction::Add => add(session, log),
            MenuAction::List => list(session, log),
            MenuAction::Copy => copy(session, log, clipboard),
            MenuAction::Update => update(session, log),
            MenuAction::Delete => delete(session, log),
            MenuAction::Exit => return 0,
        };
        match result {
            Ok(()) => {}
            Err(ActionError::Cancelled) => println!("Cancelled."),
            Err(ActionError::Prompt(e)) => return exit_code_of(&e),
            // the vault can't be read or written safely any more: stop rather than retry
            Err(ActionError::Op(e @ OpError::Storage(_))) => {
                eprintln!("Error: {e}");
                return 1;
            }
            Err(ActionError::Op(e)) => eprintln!("Error: {e}"),
        }
    }
}

fn add(session: &Session, log: &Logger) -> Result<(), ActionError> {
    let typed = Text::new("Service:").prompt()?;
    let service = actions::check_new_service(session, log, &typed)?;
    let username = Text::new("Username:").prompt()?;
    let password = Password::new("Password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_custom_confirmation_message("Confirm password:")
        .with_custom_confirmation_error_message("Passwords do not match")
        .prompt()
        .map(Zeroizing::new)?;

    actions::add(session, log, &service, &username, password)?;
    println!("Saved.");
    Ok(())
}

fn list(session: &Session, log: &Logger) -> Result<(), ActionError> {
    let listed = actions::list(session, log)?;
    if listed.is_empty() {
        println!("No credentials saved.");
    }
    for entry in listed {
        println!("{} — {}", entry.service, entry.username);
    }
    Ok(())
}

// never falls back to printing: a password must not end up in the terminal or its scrollback
fn copy(
    session: &Session,
    log: &Logger,
    clipboard: Option<&SystemClipboard>,
) -> Result<(), ActionError> {
    let Some(service) = select_service(session, log)? else {
        return Ok(());
    };
    actions::copy_password(session, log, clipboard, &service)?;
    println!(
        "Copied password for '{service}' — clipboard clears in {}s.",
        CLEAR_AFTER.as_secs()
    );
    Ok(())
}

fn update(session: &Session, log: &Logger) -> Result<(), ActionError> {
    let Some(service) = select_service(session, log)? else {
        return Ok(());
    };
    let field = Select::new(
        "Change:",
        vec![UpdateField::Username, UpdateField::Password],
    )
    .prompt()?;
    match field {
        UpdateField::Username => {
            let new = Text::new("New username:").prompt()?;
            actions::update_username(session, log, &service, &new)?;
        }
        UpdateField::Password => {
            let new = Password::new("New password:")
                .with_display_mode(PasswordDisplayMode::Masked)
                .with_custom_confirmation_message("Confirm password:")
                .with_custom_confirmation_error_message("Passwords do not match")
                .prompt()
                .map(Zeroizing::new)?;
            actions::update_password(session, log, &service, new)?;
        }
    }
    println!("Updated.");
    Ok(())
}

fn delete(session: &Session, log: &Logger) -> Result<(), ActionError> {
    let Some(service) = select_service(session, log)? else {
        return Ok(());
    };
    let confirmed = Confirm::new(&format!("Delete '{service}'?"))
        .with_default(false)
        .prompt()?;
    if !confirmed {
        return Err(ActionError::Cancelled);
    }
    actions::delete(session, log, &service)?;
    println!("Deleted.");
    Ok(())
}

// showing the names is a listing, so it is logged as one
fn select_service(session: &Session, log: &Logger) -> Result<Option<String>, ActionError> {
    let services: Vec<String> = actions::list(session, log)?
        .into_iter()
        .map(|entry| entry.service)
        .collect();
    if services.is_empty() {
        println!("No credentials saved.");
        return Ok(None);
    }
    Ok(Some(Select::new("Service:", services).prompt()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::TamperProblem;
    use std::io;
    use crate::vault::lockout::Failure;

    // the spec's two menus, in order. there is no entry that shows a password: copy only
    #[test]
    fn menus_match_the_spec() {
        let startup: Vec<String> = STARTUP.iter().map(ToString::to_string).collect();
        let main: Vec<String> = MENU.iter().map(ToString::to_string).collect();

        assert_eq!(startup, ["Log in", "Create new user", "Exit"]);
        assert_eq!(
            main,
            [
                "Add credential",
                "List credentials",
                "Copy password",
                "Update credential",
                "Delete credential",
                "Exit",
            ]
        );
        assert!(main.iter().all(|label| !label.contains("Show")));
    }

    // Esc and Ctrl-C are a normal way out; no terminal, or a terminal error, is a failure
    #[test]
    fn cancel_is_success_everything_else_is_failure() {
        assert_eq!(
            outcome_of_prompt_error(&InquireError::OperationCanceled),
            Outcome::Exit(0)
        );
        assert_eq!(
            outcome_of_prompt_error(&InquireError::OperationInterrupted),
            Outcome::Exit(0)
        );
        assert_eq!(
            outcome_of_prompt_error(&InquireError::NotTTY),
            Outcome::Exit(1)
        );
        assert_eq!(
            outcome_of_prompt_error(&InquireError::IO(io::Error::other("broken pipe"))),
            Outcome::Exit(1)
        );
    }

    // a wrong password and an unknown user must read exactly the same, and nothing shown may
    // carry a path or os error text
    #[test]
    fn login_messages_are_generic() {
        let wrong = message_for_login(&LoginError::BadCredentials {
            known_user: true,
            failure: Some(Failure {
                failures: 1,
                locked_secs: None,
            }),
        });
        let unknown = message_for_login(&LoginError::BadCredentials {
            known_user: false,
            failure: None,
        });
        assert_eq!(wrong, "Couldn't unlock vault");
        assert_eq!(unknown, wrong);

        assert_eq!(
            message_for_login(&LoginError::Locked { remaining_secs: 17 }),
            "Too many failed attempts. Try again in 17 seconds."
        );
        let io = message_for_login(&LoginError::Storage(StorageError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "/home/alice/.local/share/securevault: os error 13",
        ))));
        assert_eq!(io, "Could not access vault storage");
        assert_eq!(
            message_for_login(&LoginError::Storage(StorageError::AlreadyOpen)),
            "This vault is already open in another session"
        );
        assert_eq!(
            message_for_login(&LoginError::Storage(StorageError::AccessDenied(
                crate::vault::access::AccessCheck::Mode
            ))),
            "Access denied"
        );
    }

    // the two things the log check can have to say, in the spec's words, and silence otherwise
    #[test]
    fn log_check_messages() {
        let clean = |n| LogCheck::Clean {
            failed_attempts_since_last_session: n,
        };
        assert_eq!(message_for_log_check(&clean(0)), None);
        assert_eq!(
            message_for_log_check(&clean(2)).as_deref(),
            Some("2 failed unlock attempts for this user since your last session")
        );
        for problem in [
            TamperProblem::ChainBroken,
            TamperProblem::SealMismatch,
            TamperProblem::SealedEntryMissing,
        ] {
            assert_eq!(
                message_for_log_check(&LogCheck::Tampered(problem)).as_deref(),
                Some("Warning: the activity log was changed outside the app")
            );
        }
    }

    // the ui only prompts and prints: it never holds a decrypted vault, and every vault or
    // login operation goes through actions, which validates and logs. checked on the source,
    // since no runtime test can show that a call is missing
    #[test]
    fn ui_holds_no_vault() {
        let source = include_str!("mod.rs");
        let code = &source[..source.find("\n#[cfg(test)]\nmod tests").unwrap()];

        for call in [
            "storage::load",
            "storage::save",
            "storage::unlock",
            "storage::create_user",
            "auth::login",
        ] {
            assert!(!code.contains(call), "ui calls {call} directly");
        }
        // Vault the type, not VaultError or the file name UserFile::Vault
        let without_file_name = code.replace("UserFile::Vault", "");
        let holds_vault = without_file_name
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .any(|word| word == "Vault");
        assert!(!holds_vault, "ui names the Vault type");
    }
}
