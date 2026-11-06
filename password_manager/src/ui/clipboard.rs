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
            *self.content.lock().unwrap() = None;
            Ok(())
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
