// ============================================================================
// FILE: aescrypt-cli/src/signals.rs
// Ctrl-C / SIGTERM / SIGHUP: no temp file outlives the process, and the
// terminal is never left with echo off.
// ============================================================================
//
// `tempfile` deletes its files on drop, which a signal skips. The handler below
// deletes every registered temp file and exits 130.
//
// The prompt needs more care. rpassword turns echo and ISIG off, reads ^C as a
// byte and re-raises SIGINT *before* its guard restores the terminal, and a
// SIGTERM or SIGHUP can arrive at any point while it blocks on the read. So on
// Unix the terminal state is saved before every prompt, and a signal during
// the prompt restores it and exits at once. Nothing waits for the user to
// finish typing, and nothing is printed: after SIGHUP there may be no terminal
// left to print to.
//
// Windows has no termios to restore without `unsafe` console calls, so there
// the handler only records a signal during the prompt; rpassword then returns
// `Interrupted`, its guard restores the console mode, and the caller exits 130.

use std::{
    path::{Path, PathBuf},
    sync::{
        Mutex, Once,
        atomic::{AtomicBool, Ordering},
    },
};

static TEMPS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
static PROMPTING: AtomicBool = AtomicBool::new(false);
static INSTALL: Once = Once::new();

pub(crate) fn install() {
    INSTALL.call_once(|| {
        // Failure leaves the default disposition: worse cleanup, not wrong output.
        let _ = ctrlc::set_handler(on_signal);
    });
}

fn on_signal() {
    if PROMPTING.load(Ordering::SeqCst) {
        #[cfg(unix)]
        {
            tty::restore();
            remove_all();
            std::process::exit(130);
        }
        #[cfg(not(unix))]
        {
            PENDING.store(true, Ordering::SeqCst);
            // Re-check: if the prompt ended between the two loads, nobody will
            // look at PENDING any more, so act on the signal here.
            if PROMPTING.load(Ordering::SeqCst) {
                return;
            }
        }
    }
    remove_all();
    std::process::exit(130);
}

/// Runs `f` (a prompt) with the handler in prompt mode. `f` is told whether a
/// terminal was present when the prompt started, so a read that fails later
/// can be told apart from there never having been a terminal (always `false`
/// off Unix, where this is not detected).
pub(crate) fn prompting<T>(
    f: impl FnOnce(bool) -> Result<T, crate::CliError>,
) -> Result<T, crate::CliError> {
    #[cfg(unix)]
    let had_terminal = tty::save();
    #[cfg(not(unix))]
    let had_terminal = false;
    PROMPTING.store(true, Ordering::SeqCst);
    let result = f(had_terminal);
    PROMPTING.store(false, Ordering::SeqCst);
    #[cfg(unix)]
    tty::forget();
    #[cfg(not(unix))]
    if PENDING.load(Ordering::SeqCst) {
        return Err(crate::CliError::Interrupted);
    }
    result
}

#[cfg(not(unix))]
static PENDING: AtomicBool = AtomicBool::new(false);

pub(crate) fn register(path: &Path) {
    lock(&TEMPS).push(path.to_path_buf());
}

pub(crate) fn unregister(path: &Path) {
    lock(&TEMPS).retain(|p| p != path);
}

fn remove_all() {
    for p in lock(&TEMPS).drain(..) {
        let _ = std::fs::remove_file(p);
    }
}

fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(unix)]
mod tty {
    use std::{fs::File, sync::Mutex};

    use rustix::termios::{OptionalActions, Termios, tcgetattr, tcsetattr};

    /// The controlling terminal and its settings from just before the prompt.
    static SAVED: Mutex<Option<(File, Termios)>> = Mutex::new(None);

    /// Returns whether there is a terminal to restore.
    pub(super) fn save() -> bool {
        // No terminal: rpassword will fail on its own, nothing to restore.
        let saved = File::options()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()
            .and_then(|f| tcgetattr(&f).ok().map(|t| (f, t)));
        let present = saved.is_some();
        *super::lock(&SAVED) = saved;
        present
    }

    pub(super) fn restore() {
        if let Some((f, t)) = super::lock(&SAVED).as_ref() {
            // Fails harmlessly once the terminal has hung up.
            let _ = tcsetattr(f, OptionalActions::Now, t);
        }
    }

    pub(super) fn forget() {
        *super::lock(&SAVED) = None;
    }
}
