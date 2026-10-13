// ============================================================================
// FILE: aescrypt-cli/src/output.rs
// Writing results without ever leaving a partial or unverified file behind.
// ============================================================================
//
// Every result goes to a temp file first. Only once the library call has
// returned Ok — for decryption, that is after the HMAC and padding checks — is
// the temp file flushed to disk and renamed into place (or, for stdout, copied
// out). On any error the temp file is dropped, which deletes it; on Ctrl-C the
// signal handler deletes it.

use std::{
    fs::File,
    io::{self, BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use tempfile::NamedTempFile;

use crate::{CliError, signals};

/// A temp file registered with the signal handler for its whole life.
pub(crate) struct Staged {
    file: Option<NamedTempFile>,
    path: PathBuf,
}

impl Staged {
    /// Creates `.aescrypt-cli-*.tmp` in `dir`. Plaintext stays 0600; ciphertext
    /// is created with 0666 so the process umask decides, like any new file.
    pub(crate) fn new_in(dir: &Path, plaintext: bool) -> Result<Self, CliError> {
        let mut b = tempfile::Builder::new();
        b.prefix(".aescrypt-cli-").suffix(".tmp");
        #[cfg(unix)]
        if !plaintext {
            use std::os::unix::fs::PermissionsExt;
            b.permissions(std::fs::Permissions::from_mode(0o666));
        }
        #[cfg(not(unix))]
        let _ = plaintext;
        let file = b.tempfile_in(dir).map_err(|e| CliError::io(dir, e))?;
        let path = file.path().to_path_buf();
        signals::register(&path);
        Ok(Self {
            file: Some(file),
            path,
        })
    }

    pub(crate) fn writer(&mut self) -> BufWriter<&mut File> {
        BufWriter::new(self.file.as_mut().expect("live temp file").as_file_mut())
    }

    /// Flushes to disk and renames onto `dest`. Without `force` an existing
    /// `dest` is never replaced, even one that appeared after the preflight.
    pub(crate) fn persist(mut self, dest: &Path, force: bool) -> Result<(), CliError> {
        let file = self.file.take().expect("live temp file");
        file.as_file()
            .sync_all()
            .map_err(|e| CliError::io(&self.path, e))?;
        let result = if force {
            file.persist(dest).map(drop)
        } else {
            file.persist_noclobber(dest).map(drop)
        };
        // On failure the PersistError still owns the temp file and deletes it
        // on drop. With --force, AlreadyExists is the OS refusing (e.g. a
        // device name such as CON), so show its own message rather than
        // suggesting the flag already given.
        result.map_err(|e| {
            if !force && e.error.kind() == io::ErrorKind::AlreadyExists {
                CliError::refused(dest, "already exists (use --force to overwrite)")
            } else {
                CliError::io(dest, e.error)
            }
        })?;
        sync_parent(dest);
        Ok(())
    }

    /// Copies the finished temp file to `out`. The temp file is deleted after.
    pub(crate) fn copy_to(mut self, out: &mut dyn Write) -> Result<(), CliError> {
        let file = self.file.as_mut().expect("live temp file").as_file_mut();
        file.seek(SeekFrom::Start(0))
            .map_err(|e| CliError::io(&self.path, e))?;
        io::copy(file, out).map_err(|e| CliError::io("<stdout>", e))?;
        out.flush().map_err(|e| CliError::io("<stdout>", e))?;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // Order matters: the file is gone (or renamed) before the handler stops
        // tracking it, so there is no window where it exists untracked.
        drop(self.file.take());
        signals::unregister(&self.path);
    }
}

/// Makes the rename itself durable. Best effort: some filesystems refuse to
/// fsync a directory, and the data is already safe either way.
#[cfg(unix)]
fn sync_parent(dest: &Path) {
    let dir = match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_parent(_dest: &Path) {}

/// The folder a destination's temp file must live in, so the final rename never
/// crosses filesystems.
pub(crate) fn parent_dir(dest: &Path) -> &Path {
    match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}
