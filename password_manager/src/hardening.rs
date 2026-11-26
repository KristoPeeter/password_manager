use std::io;

use crate::ui::clipboard::{ClipboardBackend, ClipboardManager};

const PANIC_MESSAGE: &str = "Internal error";

// RLIMIT_CORE = 0, so a crash can't write the key or the vault to a core file. no-op off unix
pub fn disable_core_dumps() {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        // the hard limit too, so nothing later in the process can raise it again. best-effort:
        // if the os refuses, the app still runs
        let _ = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        );
    }
}

// the only thing a panic shows: no message, no location, nothing from memory
pub fn panic_message() -> &'static str {
    PANIC_MESSAGE
}

pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_| eprintln!("{}", panic_message())));
}

// closing the terminal (SIGHUP) or a kill (SIGTERM) still clears a copied password, then exits 1
pub fn clear_clipboard_on_signals<B: ClipboardBackend>(
    clipboard: &ClipboardManager<B>,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGHUP, SIGTERM};
        use signal_hook::iterator::Signals;

        let mut signals = Signals::new([SIGHUP, SIGTERM])?;
        // shares the same clipboard state, so it knows whether the password is still there
        let clipboard = clipboard.clone();
        std::thread::spawn(move || {
            if signals.forever().next().is_some() {
                clipboard.clear_if_unchanged();
                std::process::exit(1);
            }
        });
    }
    #[cfg(not(unix))]
    let _ = clipboard;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // a panic tells the user only that something went wrong
    #[test]
    fn panic_message_is_generic() {
        assert_eq!(panic_message(), "Internal error");
    }

    // after the call, this process can't write a core file
    #[cfg(unix)]
    #[test]
    fn core_dumps_are_disabled() {
        use rustix::process::{Resource, getrlimit};

        disable_core_dumps();

        assert_eq!(getrlimit(Resource::Core).current, Some(0));
    }
}
