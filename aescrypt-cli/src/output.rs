// ============================================================================
// FILE: aescrypt-cli/src/output.rs
// Writing results without ever leaving a partial or unverified file behind.
// ============================================================================
//
// Every file result goes to a temp file next to its destination first. Only
// once the library call has returned Ok is the temp file flushed to disk and
// put in place. On any error the temp file is dropped, which deletes it; on
// Ctrl-C the signal handler deletes it.
//
// No plaintext is ever written to a temp file that is then thrown away (#72).
// Decryption always goes through `decrypt_verified`, which checks the HMAC (and
// v3's padding) before writing anything:
//
// - A file input is read twice in place.
// - stdin can't seek, so its *ciphertext* is staged in a temp file first (next
//   to the destination, or in the temp directory for stdout) and decrypted
//   from there. Ciphertext on disk is harmless.
// - Decrypting to stdout writes the plaintext straight to stdout, in pass 2,
//   after pass 1 has verified: there is no plaintext temp file to copy from.
//
// The stage is written through its `File`, not a `BufWriter`: the library
// already writes 64 KiB spans, and a buffer would keep an unwiped copy of the
// last plaintext it held.
//
// Where the operating system can do it, the temp file is one it deletes itself
// when the last handle closes, so a forced kill (`kill -9`, `taskkill /F`),
// which nothing in the process can catch, leaves nothing behind either:
//
// - Windows: a named file opened with `FILE_FLAG_DELETE_ON_CLOSE`, put in
//   place with a hard link. Closing the handle deletes only the temp name.
// - Linux: an `O_TMPFILE` file, which has no name at all, put in place with
//   `linkat` through `/proc/self/fd`.
//
// Both use safe APIs (`std`, `rustix`). Elsewhere (macOS, other Unix), or when
// the filesystem refuses (no `O_TMPFILE`, no `/proc`, no hard links), it is an
// ordinary named temp file, renamed into place: a forced kill leaves that one.
//
// A decryption that fails verification therefore leaves its output temp file
// empty. Plaintext reaches one only in pass 2, after verification, so only an
// I/O error in pass 2 can leave a partial (verified) plaintext temp file to be
// deleted.

use std::{
    fs::File,
    io::{self, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use tempfile::NamedTempFile;

use crate::{CliError, signals};

/// Where staged bytes live until they are put in place.
enum Stage {
    /// An ordinary named temp file, deleted on drop or by the signal handler.
    Named(NamedTempFile),
    /// A named temp file opened with `FILE_FLAG_DELETE_ON_CLOSE`: Windows
    /// deletes the name when the handle closes, however the process ends.
    #[cfg(windows)]
    DeleteOnClose(NamedTempFile),
    /// An `O_TMPFILE` file with no name, in this folder: Linux frees it when
    /// the handle closes, however the process ends.
    #[cfg(target_os = "linux")]
    Unnamed {
        /// The open file.
        file: File,
        /// The folder it lives in, for error messages.
        dir: PathBuf,
    },
}

impl Stage {
    /// The open file.
    fn file_mut(&mut self) -> &mut File {
        match self {
            Stage::Named(t) => t.as_file_mut(),
            #[cfg(windows)]
            Stage::DeleteOnClose(t) => t.as_file_mut(),
            #[cfg(target_os = "linux")]
            Stage::Unnamed { file, .. } => file,
        }
    }

    /// The temp file's name, if it has one: the signal handler deletes it.
    fn name(&self) -> Option<&Path> {
        match self {
            Stage::Named(t) => Some(t.path()),
            #[cfg(windows)]
            Stage::DeleteOnClose(t) => Some(t.path()),
            #[cfg(target_os = "linux")]
            Stage::Unnamed { .. } => None,
        }
    }

    /// A path to name in error messages: the file, or its folder.
    fn label(&self) -> &Path {
        match self {
            #[cfg(target_os = "linux")]
            Stage::Unnamed { dir, .. } => dir,
            _ => self.name().expect("a named stage"),
        }
    }
}

/// A temp file, registered with the signal handler while it has a name.
pub(crate) struct Staged {
    /// The stage. `None` once `persist` has taken it.
    stage: Option<Stage>,
    /// The name registered with the signal handler, unregistered on drop.
    registered: Option<PathBuf>,
}

/// Temp file names: `.aescrypt-cli-<random>.tmp`.
fn builder() -> tempfile::Builder<'static, 'static> {
    let mut b = tempfile::Builder::new();
    b.prefix(".aescrypt-cli-").suffix(".tmp");
    b
}

impl Staged {
    /// Creates a temp file in `dir`. On Unix, plaintext stays 0600; ciphertext
    /// is created with 0666 so the process umask decides, like any new file. On
    /// Windows both inherit the folder's permissions.
    pub(crate) fn new_in(dir: &Path, plaintext: bool) -> Result<Self, CliError> {
        let stage = match os_deleted(dir, plaintext) {
            Some(stage) => stage,
            None => Stage::Named(named(dir, plaintext).map_err(|e| CliError::io(dir, e))?),
        };
        let registered = stage.name().map(Path::to_path_buf);
        if let Some(p) = &registered {
            signals::register(p);
        }
        Ok(Self {
            stage: Some(stage),
            registered,
        })
    }

    /// The temp file itself, unbuffered: to write a result into, or to read a
    /// staged ciphertext back from. No buffer sits between, so nothing keeps an
    /// unwiped copy of what passed through.
    ///
    /// # Panics
    ///
    /// If the file is gone, which only `persist` does, and it consumes `self`:
    /// this cannot happen.
    pub(crate) fn file(&mut self) -> &mut File {
        self.stage.as_mut().expect("live temp file").file_mut()
    }

    /// Flushes to disk and puts the file in place at `dest`. Without `force` an
    /// existing `dest` is never replaced, even one that appeared after the
    /// preflight.
    pub(crate) fn persist(mut self, dest: &Path, force: bool) -> Result<(), CliError> {
        let mut stage = self.stage.take().expect("live temp file");
        let label = stage.label().to_path_buf();
        stage
            .file_mut()
            .sync_all()
            .map_err(|e| CliError::io(&label, e))?;
        let result = match stage {
            Stage::Named(file) => rename_into_place(file, dest, force),
            #[cfg(windows)]
            Stage::DeleteOnClose(file) => {
                let name = file.path().to_path_buf();
                link_or_copy(dest, force, file.as_file(), |to| {
                    std::fs::hard_link(&name, to)
                })
            }
            #[cfg(target_os = "linux")]
            Stage::Unnamed { file, .. } => {
                let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
                let proc_path = format!("/proc/self/fd/{fd}");
                link_or_copy(dest, force, &file, |to| {
                    rustix::fs::linkat(
                        rustix::fs::CWD,
                        proc_path.as_str(),
                        rustix::fs::CWD,
                        to,
                        rustix::fs::AtFlags::SYMLINK_FOLLOW,
                    )
                    .map_err(io::Error::from)
                })
            }
        };
        result?;
        sync_parent(dest);
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // Order matters: the file is gone (or in place) before the handler
        // stops tracking it, so there is no window where it exists untracked.
        drop(self.stage.take());
        if let Some(p) = &self.registered {
            signals::unregister(p);
        }
    }
}

/// An ordinary named temp file in `dir`.
fn named(dir: &Path, plaintext: bool) -> io::Result<NamedTempFile> {
    #[cfg(unix)]
    if !plaintext {
        use std::os::unix::fs::PermissionsExt;
        return builder()
            .permissions(std::fs::Permissions::from_mode(0o666))
            .tempfile_in(dir);
    }
    #[cfg(not(unix))]
    let _ = plaintext;
    builder().tempfile_in(dir)
}

/// A temp file the operating system deletes when the process ends, however it
/// ends, or `None` where that is not available here. Any failure falls back to
/// a named temp file, which reports a real problem (an unwritable folder) with
/// its own error.
#[cfg(windows)]
fn os_deleted(dir: &Path, _plaintext: bool) -> Option<Stage> {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    // winbase.h / winnt.h. Others must be able to open the file with delete
    // access, for the hard link; nothing else opens it.
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    builder()
        .make_in(dir, |path| {
            OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
                .open(path)
        })
        .ok()
        .map(Stage::DeleteOnClose)
}

#[cfg(target_os = "linux")]
fn os_deleted(dir: &Path, plaintext: bool) -> Option<Stage> {
    use rustix::fs::{Mode, OFlags};
    // linkat needs /proc/self/fd to give the file a name later; without it,
    // there would be no way to put the file in place.
    if !Path::new("/proc/self/fd").is_dir() {
        return None;
    }
    let mode = if plaintext {
        Mode::RUSR | Mode::WUSR
    } else {
        Mode::from_raw_mode(0o666)
    };
    let fd = rustix::fs::openat(
        rustix::fs::CWD,
        dir,
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
        mode,
    )
    .ok()?;
    Some(Stage::Unnamed {
        file: File::from(fd),
        dir: dir.to_path_buf(),
    })
}

#[cfg(not(any(windows, target_os = "linux")))]
fn os_deleted(_dir: &Path, _plaintext: bool) -> Option<Stage> {
    None
}

/// Renames a named temp file onto `dest`.
fn rename_into_place(file: NamedTempFile, dest: &Path, force: bool) -> Result<(), CliError> {
    let result = if force {
        file.persist(dest).map(drop)
    } else {
        file.persist_noclobber(dest).map(drop)
    };
    // On failure the PersistError still owns the temp file and deletes it on
    // drop. With --force, AlreadyExists is the OS refusing (e.g. a device name
    // such as CON), so show its own message rather than suggesting the flag
    // already given.
    result.map_err(|e| persist_error(dest, force, e.error))
}

/// Turns a failure to put the file at `dest` into the CLI's message.
fn persist_error(dest: &Path, force: bool, e: io::Error) -> CliError {
    if !force && e.kind() == io::ErrorKind::AlreadyExists {
        CliError::refused(dest, "already exists (use --force to overwrite)")
    } else {
        CliError::io(dest, e)
    }
}

/// Puts an OS-deleted temp file in place with `link`, which gives the open
/// file one more name and fails with `AlreadyExists` if that name is taken.
///
/// Without `force`, it links straight to `dest`, so an existing `dest` is
/// never replaced. With `force`, it links to a fresh temp name beside `dest`
/// and renames that over it, which replaces atomically. If the filesystem
/// cannot link at all (no hard links on FAT, say), the contents are copied to
/// an ordinary named temp file, which is put in place the old way.
#[cfg(any(windows, target_os = "linux"))]
fn link_or_copy(
    dest: &Path,
    force: bool,
    file: &File,
    link: impl Fn(&Path) -> io::Result<()>,
) -> Result<(), CliError> {
    let dir = parent_dir(dest);
    let linked = if force {
        builder().make_in(dir, |name| link(name)).and_then(|named| {
            // The new name is an ordinary file now; the handler must
            // delete it if a signal arrives before the rename.
            signals::register(named.path());
            let path = named.path().to_path_buf();
            let r = named.persist(dest).map(drop).map_err(|e| e.error);
            signals::unregister(&path);
            r
        })
    } else {
        link(dest)
    };
    match linked {
        Ok(()) => Ok(()),
        Err(e) if !force && e.kind() == io::ErrorKind::AlreadyExists => {
            Err(persist_error(dest, force, e))
        }
        Err(_) => {
            let mut copy = named(dir, true).map_err(|e| CliError::io(dir, e))?;
            signals::register(copy.path());
            let path = copy.path().to_path_buf();
            let result = (|| {
                let mut src = file;
                src.seek(SeekFrom::Start(0))?;
                io::copy(&mut src, copy.as_file_mut())?;
                copy.as_file().sync_all()
            })()
            .map_err(|e| CliError::io(&path, e))
            .and_then(|()| rename_into_place(copy, dest, force));
            signals::unregister(&path);
            result
        }
    }
}

/// Makes the rename itself durable. Best effort: some filesystems refuse to
/// fsync a directory, and the data is already safe either way.
#[cfg(unix)]
fn sync_parent(dest: &Path) {
    if let Ok(d) = File::open(parent_dir(dest)) {
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
