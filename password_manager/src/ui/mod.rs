pub(crate) mod clipboard;

use std::{
    fmt,
    io::{self, IsTerminal, Write},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use inquire::{
    Confirm, InquireError, Password, PasswordDisplayMode, Select, Text, validator::Validation,
};
use zeroize::Zeroizing;

use clipboard::{CLEAR_AFTER, ClipboardManager};

use crate::actions::{self, Listed, LoggedIn, OpError};
use crate::audit::{Event, LogCheck, Logger};
use crate::hardening;
use crate::paths::{DataDir, PathsError, Username};
use crate::vault::access::AccessError;
use crate::vault::auth::LoginError;
use crate::vault::lockout::LockState;
use crate::vault::storage::{Session, StorageError};
use crate::vault::validation;

// the ui only prompts and prints. every vault or login operation goes through actions, which
// validates, saves and logs; no decrypted vault is ever held here

const UNLOCK_ATTEMPTS: usize = 3;
const STORAGE_UNAVAILABLE: &str = "Could not access vault storage";
const NO_CREDENTIALS: &str = "No credentials saved.";
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

// why the data folder can't be used, for the one message shown before exiting
#[derive(Debug)]
pub(crate) enum DataDirError {
    Paths(PathsError),
    Access(AccessError),
}

// says which setup problem it is, so the user can fix it; still no path and no os error text
pub(crate) fn message_for_data_dir(e: &DataDirError) -> String {
    match e {
        DataDirError::Paths(e) => e.to_string(),
        DataDirError::Access(AccessError::Denied(_)) => "Access denied".to_string(),
        DataDirError::Access(AccessError::Io(_)) => STORAGE_UNAVAILABLE.to_string(),
    }
}

fn open_data_dir() -> Result<DataDir, DataDirError> {
    let data = DataDir::resolve().map_err(DataDirError::Paths)?;
    data.ensure().map_err(DataDirError::Access)?;
    Ok(data)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn run() -> ExitCode {
    hardening::install_panic_hook();
    hardening::disable_core_dumps();

    let data = match open_data_dir() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{}", message_for_data_dir(&e));
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
                let first = status_after_login(&logged_in.check);
                let code = main_menu(&logged_in.session, log, clipboard, first);
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
    match actions::check_new_user(data, log, &user) {
        Ok(()) => {}
        Err(e @ StorageError::UserExists) => {
            eprintln!("{e}");
            return Step::Back;
        }
        Err(e) => {
            eprintln!("{e}");
            return Step::Exit(1);
        }
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
#[derive(Debug)]
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

// the one line left above the menu after the screen is cleared: what the last action did, or what went wrong
#[derive(Debug, PartialEq)]
pub(crate) enum Status {
    Info(String),
    // printed to stderr
    Error(String),
}

// what the menu loop does after an action
#[derive(Debug, PartialEq)]
pub(crate) enum MenuStep {
    Show(Option<Status>),
    // the status is printed before leaving, so the reason stays visible
    Exit { code: u8, status: Option<Status> },
}

// clears what is visible and moves the cursor home. not the scrollback: that is the user's own terminal history from before the app
pub(crate) fn clear_screen_code() -> &'static str {
    "\x1b[2J\x1b[H"
}

// an action returns the line to show (Saved., Deleted., ...) or None when it showed its own screen, like list
fn menu_step(result: Result<Option<String>, ActionError>) -> MenuStep {
    match result {
        Ok(message) => MenuStep::Show(message.map(Status::Info)),
        Err(ActionError::Cancelled) => MenuStep::Show(Some(Status::Info("Cancelled.".into()))),
        Err(ActionError::Prompt(e)) => MenuStep::Exit {
            code: exit_code_of(&e),
            status: None,
        },
        // the vault can't be read or written safely any more: stop rather than retry
        Err(ActionError::Op(e @ OpError::Storage(_))) => MenuStep::Exit {
            code: 1,
            status: Some(Status::Error(format!("Error: {e}"))),
        },
        Err(ActionError::Op(e)) => MenuStep::Show(Some(Status::Error(format!("Error: {e}")))),
    }
}

// the log check's message becomes the first status line, so clearing the screen doesn't hide it
pub(crate) fn status_after_login(check: &LogCheck) -> Option<Status> {
    let message = message_for_log_check(check)?;
    Some(match check {
        LogCheck::Tampered(_) => Status::Error(message),
        LogCheck::Clean { .. } => Status::Info(message),
    })
}

// what list shows before it waits
pub(crate) fn list_lines(entries: &[Listed]) -> Vec<String> {
    if entries.is_empty() {
        return vec![NO_CREDENTIALS.to_string()];
    }
    entries
        .iter()
        .map(|entry| format!("{} — {}", entry.service, entry.username))
        .collect()
}

// the pause after list: Enter or Esc both just go back, Ctrl-C and terminal errors still end the app
fn after_pause(result: Result<(), InquireError>) -> Result<(), ActionError> {
    match result {
        Ok(()) | Err(InquireError::OperationCanceled) => Ok(()),
        Err(e) => Err(ActionError::Prompt(e)),
    }
}

fn show(status: &Status) {
    match status {
        Status::Info(text) => println!("{text}"),
        Status::Error(text) => eprintln!("{text}"),
    }
}

// only on a terminal: piped output would just get the escape codes
fn clear_screen() {
    let mut out = io::stdout();
    if out.is_terminal() {
        let _ = write!(out, "{}", clear_screen_code());
        let _ = out.flush();
    }
}

// the menu comes first and each action loads what it needs, so nothing decrypted waits here
fn main_menu(
    session: &Session,
    log: &Logger,
    clipboard: Option<&SystemClipboard>,
    first: Option<Status>,
) -> u8 {
    let mut status = first;
    loop {
        // a clean screen each time: only the menu and what the last action did
        clear_screen();
        if let Some(status) = &status {
            show(status);
        }
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
        match menu_step(result) {
            MenuStep::Show(next) => status = next,
            MenuStep::Exit { code, status } => {
                if let Some(status) = &status {
                    show(status);
                }
                return code;
            }
        }
    }
}

// each action returns the line to show above the next menu, or None when it had its own screen

fn add(session: &Session, log: &Logger) -> Result<Option<String>, ActionError> {
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
    Ok(Some("Saved.".into()))
}

// the list stays on screen until the user is done reading it
fn list(session: &Session, log: &Logger) -> Result<Option<String>, ActionError> {
    let listed = actions::list(session, log)?;
    for line in list_lines(&listed) {
        println!("{line}");
    }
    let pause = Select::new("Press Enter to go back", vec!["Back"])
        .without_help_message()
        .prompt()
        .map(|_| ());
    after_pause(pause)?;
    Ok(None)
}

// never falls back to printing: a password must not end up in the terminal or its scrollback
fn copy(
    session: &Session,
    log: &Logger,
    clipboard: Option<&SystemClipboard>,
) -> Result<Option<String>, ActionError> {
    let Some(service) = select_service(session, log)? else {
        return Ok(Some(NO_CREDENTIALS.into()));
    };
    actions::copy_password(session, log, clipboard, &service)?;
    Ok(Some(format!(
        "Copied password for '{service}' — clipboard clears in {}s.",
        CLEAR_AFTER.as_secs()
    )))
}

fn update(session: &Session, log: &Logger) -> Result<Option<String>, ActionError> {
    let Some(service) = select_service(session, log)? else {
        return Ok(Some(NO_CREDENTIALS.into()));
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
    Ok(Some("Updated.".into()))
}

fn delete(session: &Session, log: &Logger) -> Result<Option<String>, ActionError> {
    let Some(service) = select_service(session, log)? else {
        return Ok(Some(NO_CREDENTIALS.into()));
    };
    let confirmed = Confirm::new(&format!("Delete '{service}'?"))
        .with_default(false)
        .prompt()?;
    if !confirmed {
        return Err(ActionError::Cancelled);
    }
    actions::delete(session, log, &service)?;
    Ok(Some("Deleted.".into()))
}

// showing the names is a listing, so it is logged as one. None when there is nothing to pick
fn select_service(session: &Session, log: &Logger) -> Result<Option<String>, ActionError> {
    let services: Vec<String> = actions::list(session, log)?
        .into_iter()
        .map(|entry| entry.service)
        .collect();
    if services.is_empty() {
        return Ok(None);
    }
    Ok(Some(Select::new("Service:", services).prompt()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::TamperProblem;
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

    // a setup problem says which one it is; an os error still shows only the fixed text
    #[test]
    fn startup_messages_say_what_is_wrong() {
        use crate::vault::access::AccessCheck;
        let cases = [
            (
                DataDirError::Paths(PathsError::NotAbsolute),
                "SECUREVAULT_HOME must be an absolute path",
            ),
            (
                DataDirError::Paths(PathsError::ParentComponent),
                "SECUREVAULT_HOME must not contain \"..\"",
            ),
            (
                DataDirError::Paths(PathsError::NoHome),
                "Couldn't find a folder to store data in",
            ),
            (
                DataDirError::Access(AccessError::Denied(AccessCheck::Mode)),
                "Access denied",
            ),
            (
                DataDirError::Access(AccessError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "/home/alice/.local/share/securevault: os error 13",
                ))),
                "Could not access vault storage",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(message_for_data_dir(&error), expected, "{error:?}");
        }
    }

    // exists() follows links: a dangling one at a vault path reads as "nothing there". the ui asks actions instead, which looks at the entry itself
    #[test]
    fn ui_never_checks_a_path_itself() {
        let source = include_str!("mod.rs");
        let code = &source[..source.find("\n#[cfg(test)]\nmod tests").unwrap()];

        for call in [".exists()", ".try_exists()", "fs::"] {
            assert!(!code.contains(call), "ui calls {call}");
        }
    }

    fn info(text: &str) -> Option<Status> {
        Some(Status::Info(text.to_string()))
    }

    fn error(text: &str) -> Option<Status> {
        Some(Status::Error(text.to_string()))
    }

    // the visible screen is cleared and the cursor goes home; the scrollback (ESC[3J) is left alone
    #[test]
    fn clearing_keeps_the_scrollback() {
        assert_eq!(clear_screen_code(), "\x1b[2J\x1b[H");
    }

    // after each action the menu comes back on a clean screen with one line saying what happened
    #[test]
    fn each_outcome_leaves_one_status_line() {
        assert_eq!(
            menu_step(Ok(Some("Saved.".to_string()))),
            MenuStep::Show(info("Saved."))
        );
        // list showed its own screen and waited, so nothing is left to say
        assert_eq!(menu_step(Ok(None)), MenuStep::Show(None));
        assert_eq!(
            menu_step(Err(ActionError::Cancelled)),
            MenuStep::Show(info("Cancelled."))
        );
        assert_eq!(
            menu_step(Err(ActionError::Op(OpError::Vault(
                crate::vault::models::VaultError::DuplicateService
            )))),
            MenuStep::Show(error("Error: Credential already exists"))
        );
        assert_eq!(
            menu_step(Err(ActionError::Op(OpError::ClipboardUnavailable))),
            MenuStep::Show(error("Error: Clipboard unavailable"))
        );
    }

    // a storage failure still ends the session, and says why before it does; leaving a prompt keeps its exit code
    #[test]
    fn failures_that_end_the_session_keep_their_message() {
        assert_eq!(
            menu_step(Err(ActionError::Op(OpError::Storage(StorageError::Io(
                io::Error::new(io::ErrorKind::PermissionDenied, "/home/alice: os error 13")
            ))))),
            MenuStep::Exit {
                code: 1,
                status: error("Error: Could not access vault storage"),
            }
        );
        assert_eq!(
            menu_step(Err(ActionError::Prompt(InquireError::OperationInterrupted))),
            MenuStep::Exit {
                code: 0,
                status: None
            }
        );
        assert_eq!(
            menu_step(Err(ActionError::Prompt(InquireError::NotTTY))),
            MenuStep::Exit {
                code: 1,
                status: None
            }
        );
    }

    // the log check's warning survives the first clear: it is the first status line
    #[test]
    fn log_check_is_the_first_status_line() {
        let clean = |n| LogCheck::Clean {
            failed_attempts_since_last_session: n,
        };
        assert_eq!(status_after_login(&clean(0)), None);
        assert_eq!(
            status_after_login(&clean(2)),
            info("2 failed unlock attempts for this user since your last session")
        );
        assert_eq!(
            status_after_login(&LogCheck::Tampered(TamperProblem::ChainBroken)),
            error("Warning: the activity log was changed outside the app")
        );
    }

    // one line per credential, and a plain sentence for an empty vault
    #[test]
    fn list_shows_service_and_username() {
        let entries = [
            Listed {
                service: "github".to_string(),
                username: "alice".to_string(),
            },
            Listed {
                service: "mail".to_string(),
                username: String::new(),
            },
        ];
        assert_eq!(list_lines(&entries), ["github — alice", "mail — "]);
        assert_eq!(list_lines(&[]), ["No credentials saved."]);
    }

    // Enter and Esc on the pause both just go back to the menu; Ctrl-C and a broken terminal don't
    #[test]
    fn pause_after_list_goes_back() {
        assert!(after_pause(Ok(())).is_ok());
        assert!(after_pause(Err(InquireError::OperationCanceled)).is_ok());
        assert!(matches!(
            after_pause(Err(InquireError::OperationInterrupted)),
            Err(ActionError::Prompt(InquireError::OperationInterrupted))
        ));
        assert!(matches!(
            after_pause(Err(InquireError::NotTTY)),
            Err(ActionError::Prompt(InquireError::NotTTY))
        ));
    }
}
