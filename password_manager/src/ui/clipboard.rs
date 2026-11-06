use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

pub const CLEAR_AFTER: Duration = Duration::from_secs(20);

#[derive(Debug, PartialEq)]
pub struct ClipboardError;

pub trait ClipboardBackend: Send + 'static {
    fn set_text(&mut self, text: &str) -> Result<(), ClipboardError>;
    fn get_text(&mut self) -> Result<String, ClipboardError>;
    fn clear(&mut self) -> Result<(), ClipboardError>;
}
impl ClipboardBackend for arboard::Clipboard {
    fn set_text(&mut self, text: &str) -> Result<(), ClipboardError> {
        arboard::Clipboard::set_text(self, text).map_err(|_| ClipboardError)
    }
    fn get_text(&mut self) -> Result<String, ClipboardError> {
        arboard::Clipboard::get_text(self).map_err(|_| ClipboardError)
    }
}

struct State<B> {
    backend: B,
    generation: u64,
    pending: Option<Zeroizing<String>>,
}
pub struct ClipboardManager<B: ClipboardBackend> {
    state: Arc<Mutex<State<B>>>,
    clear_after: Duration,
}

//if anybody tries to poison the mutex
fn lock<B>(state: &Mutex<State<B>>) -> MutexGuard<'_, State<B>> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

fn clear_if_pending<B: ClipboardBackend>(state: &mut State<B>) {
    if let Some(pending) = state.pending.take() {
        let still_ours = state
            .backend
            .get_text()
            .map(Zeroizing::new)
            .is_ok_and(|current| *current == *pending);
        if still_ours {
            let _ = state.backend.clear();
        }
    }
}

impl<B: ClipboardBackend> ClipboardManager<B> {
    pub fn new(backend: B, clear_after: Duration) -> Self {
        let state = State {
            backend,
            generation: 0,
            pending: None,
        };
        Self {
            state: Arc::new(Mutex::new(state)),
            clear_after,
        }
    }

    pub fn copy(&self, secret: &str) -> Result<(), ClipboardError> {
        let my_gen = {
            let mut state = lock(&self.state);
            state.backend.set_text(secret)?;
            state.generation += 1;
            state.pending = Some(Zeroizing::new(secret.to_string()));
            state.generation
        };
        let state = Arc::clone(&self.state);
        let clear_after = self.clear_after;
        thread::spawn(move || {
            thread::sleep(clear_after);
            let mut state = lock(&state);
            if state.generation == my_gen {
                clear_if_pending(&mut state);
            }
        });
        Ok(())
    }
    pub fn clear_if_unchanged(&self) {
        clear_if_pending(&mut lock(&self.state));
    }
}

pub fn system() -> Result<ClipboardManager<arboard::Clipboard>, ClipboardError> {
    let backend = arboard::Clipboard::new().map_err(|_| ClipboardError)?;
    Ok(ClipboardManager::new(backend, CLEAR_AFTER))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::sleep;
    use std::time::Duration;

    const CLEAR_AFTER_TEST: Duration = Duration::from_millis(100);

    // fake clipboard so tests never touch the real one
    #[derive(Clone, Default)]
    struct Fake {
        content: Arc<Mutex<Option<String>>>,
        fail: Arc<AtomicBool>,
    }

    impl ClipboardBackend for Fake {
        fn set_text(&mut self, text: &str) -> Result<(), ClipboardError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(ClipboardError);
            }
            *self.content.lock().unwrap() = Some(text.to_string());
            Ok(())
        }

        fn get_text(&mut self) -> Result<String, ClipboardError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(ClipboardError);
            }
            self.content.lock().unwrap().clone().ok_or(ClipboardError)
        }

        fn clear(&mut self) -> Result<(), ClipboardError> {
            arboard::Clipboard::clear(self).map_err(|_| ClipboardError)
        }
    }

    fn manager() -> (ClipboardManager<Fake>, Fake) {
        let fake = Fake::default();
        (ClipboardManager::new(fake.clone(), CLEAR_AFTER_TEST), fake)
    }

    fn read(fake: &Fake) -> Option<String> {
        fake.content.lock().unwrap().clone()
    }

    fn user_copies(fake: &Fake, text: &str) {
        *fake.content.lock().unwrap() = Some(text.to_string());
    }

    // copying puts the password on the clipboard
    #[test]
    fn copy_puts_secret_on_clipboard() {
        let (clipboard, fake) = manager();

        clipboard.copy("pw1").unwrap();

        assert_eq!(read(&fake), Some("pw1".to_string()));
    }

    // the password is wiped from the clipboard after the timeout
    #[test]
    fn clears_after_timeout() {
        let (clipboard, fake) = manager();

        clipboard.copy("pw1").unwrap();
        sleep(Duration::from_millis(300));

        assert_eq!(read(&fake), None);
    }

    // if the user copied something else meanwhile we leave it alone
    #[test]
    fn does_not_clear_if_user_copied_something_else() {
        let (clipboard, fake) = manager();

        clipboard.copy("pw1").unwrap();
        user_copies(&fake, "user text");
        sleep(Duration::from_millis(300));

        assert_eq!(read(&fake), Some("user text".to_string()));
    }

    // an old timer must not wipe a newer copy, each copy gets the full timeout
    #[test]
    fn second_copy_restarts_timer() {
        let (clipboard, fake) = manager();

        clipboard.copy("pw1").unwrap();
        sleep(Duration::from_millis(60));
        clipboard.copy("pw2").unwrap();
        sleep(Duration::from_millis(70));
        assert_eq!(read(&fake), Some("pw2".to_string()));

        sleep(Duration::from_millis(200));
        assert_eq!(read(&fake), None);
    }

    // on exit the clipboard is wiped right away, no waiting
    #[test]
    fn clear_if_unchanged_clears_immediately() {
        let (clipboard, fake) = manager();

        clipboard.copy("pw1").unwrap();
        clipboard.clear_if_unchanged();

        assert_eq!(read(&fake), None);
    }

    // on exit we still leave the user's own clipboard content alone
    #[test]
    fn clear_if_unchanged_keeps_user_content() {
        let (clipboard, fake) = manager();

        clipboard.copy("pw1").unwrap();
        user_copies(&fake, "user text");
        clipboard.clear_if_unchanged();

        assert_eq!(read(&fake), Some("user text".to_string()));
    }

    // a failed copy reports an error and doesn't schedule a clear for something never copied
    #[test]
    fn copy_failure_returns_error_and_leaves_no_pending_clear() {
        let (clipboard, fake) = manager();
        fake.fail.store(true, Ordering::SeqCst);

        assert_eq!(clipboard.copy("pw1"), Err(ClipboardError));

        fake.fail.store(false, Ordering::SeqCst);
        user_copies(&fake, "x");
        clipboard.clear_if_unchanged();
        assert_eq!(read(&fake), Some("x".to_string()));
    }
}
