// run() (task 11) is the only caller; until then only the tests use this module
#![allow(dead_code)]

use std::io;

use crate::ui::clipboard::{ClipboardBackend, ClipboardManager};

// RLIMIT_CORE = 0, so a crash can't write the key or the vault to a core file. no-op off unix
pub fn disable_core_dumps() {
    todo!("task 11")
}

// the only thing a panic shows: no message, no location, nothing from memory
pub fn panic_message() -> &'static str {
    todo!("task 11")
}

pub fn install_panic_hook() {
    todo!("task 11")
}

// closing the terminal (SIGHUP) or a kill (SIGTERM) still clears a copied password, then exits 1
pub fn clear_clipboard_on_signals<B: ClipboardBackend>(
    clipboard: &ClipboardManager<B>,
) -> io::Result<()> {
    let _ = clipboard;
    todo!("task 11")
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
