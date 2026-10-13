// ============================================================================
// FILE: aescrypt-cli/src/signals.rs
// Ctrl-C / SIGTERM / SIGHUP: no temp file outlives the process, and the
// terminal is never left with echo off.
// ============================================================================
//
// `tempfile` deletes its files on drop, which a signal skips. The handler below
// deletes every registered temp file and exits 130.
//
// The prompt needs more care. rpassword turns echo off and blocks on the read,
// and a signal can arrive at any point while it does. On Unix it also turns
// ISIG off, reads ^C as a byte and re-raises SIGINT *before* its guard restores
// the terminal. On Windows, Ctrl-C does not end the console read at all: it
// waits for Enter. So the terminal state (termios on Unix, the console input
// mode on Windows) is saved before every prompt, and a signal during the
// prompt restores it and exits at once. Nothing waits for the user to finish
// typing, and nothing is printed: after SIGHUP there may be no terminal left
// to print to.

use std::{
    path::{Path, PathBuf},
    sync::{
        Mutex, Once,
        atomic::{AtomicBool, Ordering},
    },
};

/// Temp files that exist right now; the handler deletes them all.
static TEMPS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
/// Whether a password prompt is in progress, so the handler restores the
/// terminal before exiting.
static PROMPTING: AtomicBool = AtomicBool::new(false);
/// Makes [`install`] idempotent.
static INSTALL: Once = Once::new();

/// Installs the handler for Ctrl-C, SIGTERM and SIGHUP (the console close
/// events on Windows), once per process. If installing fails, the default
/// behavior stays: worse cleanup, not wrong output.
pub(crate) fn install() {
    INSTALL.call_once(|| {
        // Failure leaves the default disposition: worse cleanup, not wrong output.
        let _ = ctrlc::set_handler(on_signal);
    });
}

/// The handler. Runs on its own thread: restores the terminal if a prompt is in
/// progress, deletes every registered temp file, and exits 130.
fn on_signal() {
    if PROMPTING.load(Ordering::SeqCst) {
        // If the prompt ended a moment ago, this restores the same state the
        // prompt itself just restored: harmless.
        #[cfg(unix)]
        tty::restore();
        #[cfg(windows)]
        con::restore();
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
    #[cfg(windows)]
    con::save();
    PROMPTING.store(true, Ordering::SeqCst);
    let result = f(had_terminal);
    PROMPTING.store(false, Ordering::SeqCst);
    #[cfg(unix)]
    tty::forget();
    #[cfg(windows)]
    con::forget();
    result
}

/// Whether the terminal the current prompt started on has since hung up. Only
/// meaningful inside the closure given to [`prompting`]; always `false` off
/// Unix.
pub(crate) fn terminal_hung_up() -> bool {
    #[cfg(unix)]
    return tty::hung_up();
    #[cfg(not(unix))]
    false
}

/// Tracks a new temp file so a signal deletes it.
pub(crate) fn register(path: &Path) {
    lock(&TEMPS).push(path.to_path_buf());
}

/// Stops tracking a temp file once it has been deleted or renamed.
pub(crate) fn unregister(path: &Path) {
    lock(&TEMPS).retain(|p| p != path);
}

/// Deletes every tracked temp file, ignoring failures: the process is exiting.
fn remove_all() {
    for p in lock(&TEMPS).drain(..) {
        let _ = std::fs::remove_file(p);
    }
}

/// Locks `m`, recovering from poisoning: the handler must still be able to
/// clean up after a panic on another thread.
fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Saving and restoring the Unix terminal's termios around the prompt.
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

    /// Puts the saved settings back, turning echo on again.
    pub(super) fn restore() {
        if let Some((f, t)) = super::lock(&SAVED).as_ref() {
            // Fails harmlessly once the terminal has hung up.
            let _ = tcsetattr(f, OptionalActions::Now, t);
        }
    }

    /// Whether the saved terminal has hung up. Linux fails the read (EIO), but
    /// macOS ends it like an empty line, which rpassword returns as `Ok("")`.
    /// A write of nothing tells them apart: it fails with EIO once the
    /// terminal has hung up (on both systems), and on a live terminal it does
    /// nothing at all. Nothing is read, so typeahead stays for whatever runs
    /// next. `poll` is no use here: on macOS the read can end before the
    /// hang-up shows there.
    pub(super) fn hung_up() -> bool {
        match super::lock(&SAVED).as_ref() {
            Some((f, _)) => rustix::io::write(f, b"").is_err(),
            None => false,
        }
    }

    /// Drops the saved terminal once the prompt has ended.
    pub(super) fn forget() {
        *super::lock(&SAVED) = None;
    }
}

/// Saving and restoring the Windows console input mode around the prompt.
#[cfg(windows)]
mod con {
    use std::{fs::File, sync::Mutex};

    use winapi_util::console;

    /// The console input buffer and its mode from just before the prompt. The
    /// mode belongs to the console, not to a handle, so restoring it through
    /// this handle undoes what rpassword set through its own.
    static SAVED: Mutex<Option<(File, u32)>> = Mutex::new(None);

    /// Records the console input mode before the prompt changes it.
    pub(super) fn save() {
        // No console: rpassword will fail on its own, nothing to restore.
        let saved = File::options()
            .read(true)
            .write(true)
            .open("CONIN$")
            .ok()
            .and_then(|f| console::mode(&f).ok().map(|m| (f, m)));
        *super::lock(&SAVED) = saved;
    }

    /// Puts the saved mode back, turning echo on again.
    pub(super) fn restore() {
        if let Some((f, mode)) = super::lock(&SAVED).as_ref() {
            let _ = console::set_mode(f, *mode);
        }
    }

    /// Drops the saved console once the prompt has ended.
    pub(super) fn forget() {
        *super::lock(&SAVED) = None;
    }
}
