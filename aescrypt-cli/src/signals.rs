// ============================================================================
// FILE: aescrypt-cli/src/signals.rs
// Ctrl-C / SIGTERM handling: no temp file outlives the process.
// ============================================================================
//
// `tempfile` deletes its files on drop, which a signal skips. The handler below
// deletes every registered temp file and exits 130.
//
// It is installed before the password prompt, not after, because of how
// rpassword handles Ctrl-C: it clears ISIG, reads ^C as a byte, and re-raises
// SIGINT *before* its guard restores echo. With the default disposition that
// kills the process and leaves the terminal with echo off. So while a prompt
// is active the handler only records the signal; rpassword then returns
// `Interrupted`, its guard restores the terminal, and the caller exits 130.
// A SIGTERM during a prompt is likewise deferred until the prompt returns.

use std::{
    path::{Path, PathBuf},
    sync::{
        Mutex, Once,
        atomic::{AtomicBool, Ordering},
    },
};

static TEMPS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
static PROMPTING: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicBool = AtomicBool::new(false);
static INSTALL: Once = Once::new();

pub(crate) fn install() {
    INSTALL.call_once(|| {
        // Failure leaves the default disposition: worse cleanup, not wrong output.
        let _ = ctrlc::set_handler(|| {
            if PROMPTING.load(Ordering::SeqCst) {
                PENDING.store(true, Ordering::SeqCst);
                return;
            }
            remove_all();
            std::process::exit(130);
        });
    });
}

/// Runs `f` with the handler in prompt mode. Returns `Interrupted` if a signal
/// arrived meanwhile, even when `f` itself succeeded.
pub(crate) fn prompting<T>(
    f: impl FnOnce() -> Result<T, crate::CliError>,
) -> Result<T, crate::CliError> {
    PROMPTING.store(true, Ordering::SeqCst);
    let result = f();
    // Stays set on the error path: a late handler run must not exit before the
    // caller has printed its message.
    if result.is_ok() {
        PROMPTING.store(false, Ordering::SeqCst);
    }
    if PENDING.load(Ordering::SeqCst) {
        return Err(crate::CliError::Interrupted);
    }
    result
}

pub(crate) fn register(path: &Path) {
    lock().push(path.to_path_buf());
}

pub(crate) fn unregister(path: &Path) {
    lock().retain(|p| p != path);
}

fn remove_all() {
    for p in lock().drain(..) {
        let _ = std::fs::remove_file(p);
    }
}

fn lock() -> std::sync::MutexGuard<'static, Vec<PathBuf>> {
    TEMPS.lock().unwrap_or_else(|e| e.into_inner())
}
