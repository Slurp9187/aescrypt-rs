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
// No plaintext is ever written to a temp file in the clear, except the output
// file itself (#72). Decryption always goes through `decrypt_verified`, which
// checks the HMAC (and v3's padding) before writing anything:
//
// - A file input is read twice in place.
// - stdin can't seek, so its *ciphertext* is staged in an owner-only temp file
//   first (next to the destination, or in the temp directory for stdout) and
//   decrypted from there.
// - Decrypting to stdout stages pass 2's plaintext in a `Sealed` file:
//   AES-256-CTR under a random key held only in memory. It is copied out to
//   stdout only once the whole call has succeeded, so stdout gets all of the
//   plaintext or none of it, and the disk only ever holds noise.
//
// Plaintext is written to its stage unbuffered: a `BufWriter` would keep an
// unwiped copy of the last plaintext it held, and the library already writes
// whole spans. Ciphertext sides are buffered.
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
// empty. Plaintext reaches a file destination's temp file only in pass 2, after
// verification. An I/O error, a changed input or a signal during pass 2 can
// leave part of that verified plaintext in it, to be deleted unwiped; that file
// is the output itself, so this cannot be avoided by sealing.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit, consts::U16, inout::InOutBuf},
};
use secure_gate::{Dynamic, Fixed, RevealSecret, RevealSecretMut};

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
    /// Creates a temp file in `dir`. On Unix a `private` one is 0600 (plaintext
    /// outputs, and every stage that is not the output: stdin's ciphertext, the
    /// sealed stdout stage); otherwise it is created with 0666 so the process
    /// umask decides, like any new file (an encrypted output). On Windows both
    /// inherit the folder's permissions.
    pub(crate) fn new_in(dir: &Path, private: bool) -> Result<Self, CliError> {
        let stage = match os_deleted(dir, private) {
            Some(stage) => stage,
            None => Stage::Named(named(dir, private).map_err(|e| CliError::io(dir, e))?),
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

    /// A path to name in error messages: the file, or its folder.
    ///
    /// # Panics
    ///
    /// If the file is gone, which only `persist` does: this cannot happen.
    fn label(&self) -> &Path {
        self.stage.as_ref().expect("live temp file").label()
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

/// Bytes sealed per step: plaintext is copied into the stage's wiped chunk,
/// sealed in place, and written. 64 KiB, the library's largest span: at 4 KiB,
/// decrypting 1 GiB to stdout took over twice as long as decrypting to a file.
const SEAL_CHUNK: usize = 64 * 1024;

/// A zeroed heap buffer of `len` bytes, wiped on drop. `vec![0u8; len]` is
/// allocated zeroed at exactly `len`, so nothing this size goes on the stack,
/// and a boxed slice cannot grow and leave an unwiped copy behind.
fn wiped_buffer(len: usize) -> Dynamic<[u8]> {
    Dynamic::new(vec![0u8; len])
}

/// A private stage whose bytes are sealed before they reach the disk:
/// AES-256-CTR under a key made for this stage alone and held only in memory.
/// Decrypting to stdout writes its plaintext here (#72), and `copy_out` unseals
/// it to stdout once the whole decryption has succeeded, so stdout gets all of
/// it or nothing. If the process ends any other way, the key goes with it and
/// what is on disk (deleted like any stage) is noise.
///
/// No integrity: someone who can write the temp file while it runs could flip
/// output bits, exactly as with the plaintext stage this replaces.
pub(crate) struct Sealed {
    /// The temp file the sealed bytes go to.
    staged: Staged,
    /// AES-256 under the stage's key; its key schedule is wiped on drop.
    cipher: Aes256,
    /// Bytes written so far: the keystream position of the next one.
    written: u64,
    /// `SEAL_CHUNK` bytes, reused by every write and by `copy_out`.
    chunk: Dynamic<[u8]>,
    /// `SEAL_CHUNK + 16` bytes of keystream, reused likewise.
    keystream: Dynamic<[u8]>,
}

impl Sealed {
    /// A sealed stage in `dir`, under a fresh random key.
    pub(crate) fn new_in(dir: &Path) -> Result<Self, CliError> {
        let staged = Staged::new_in(dir, true)?;
        let key = Fixed::<[u8; 32]>::from_random();
        let cipher = key.with_secret(|k| Aes256::new(k.into()));
        Ok(Self {
            staged,
            cipher,
            written: 0,
            chunk: wiped_buffer(SEAL_CHUNK),
            keystream: wiped_buffer(SEAL_CHUNK + 16),
        })
    }

    /// Unseals the stage into `out`, from the start. Call only after the
    /// decryption has succeeded. The stage is deleted after.
    pub(crate) fn copy_out(mut self, out: &mut dyn Write) -> Result<(), CliError> {
        let label = self.staged.label().to_path_buf();
        let Self {
            staged,
            cipher,
            chunk,
            keystream,
            ..
        } = &mut self;
        let file = staged.file();
        file.seek(SeekFrom::Start(0))
            .map_err(|e| CliError::io(&label, e))?;
        let mut pos = 0u64;
        loop {
            let n = match chunk.with_secret_mut(|c| file.read(c)) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(CliError::io(&label, e)),
            };
            chunk.with_secret_mut(|c| {
                keystream.with_secret_mut(|ks| apply_keystream(cipher, pos, &mut c[..n], ks))
            });
            chunk
                .with_secret(|c| out.write_all(&c[..n]))
                .map_err(|e| CliError::io("<stdout>", e))?;
            pos += n as u64;
        }
        Ok(())
    }
}

impl Write for Sealed {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(SEAL_CHUNK);
        let Self {
            staged,
            cipher,
            written,
            chunk,
            keystream,
        } = self;
        chunk.with_secret_mut(|c| {
            c[..n].copy_from_slice(&data[..n]);
            keystream.with_secret_mut(|ks| apply_keystream(cipher, *written, &mut c[..n], ks));
        });
        chunk.with_secret(|c| staged.file().write_all(&c[..n]))?;
        *written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.staged.file().flush()
    }
}

/// XORs the AES-256-CTR keystream for byte offset `pos` onward into `data`
/// (at most `SEAL_CHUNK` bytes), building it in `ks` (`SEAL_CHUNK + 16` bytes:
/// up to 15 skipped bytes plus `data`, rounded up to whole blocks). Counter
/// block `i` is `i` as a big-endian 128-bit number; each stage has its own
/// random key, so no counter repeats under a key.
fn apply_keystream(cipher: &Aes256, pos: u64, data: &mut [u8], ks: &mut [u8]) {
    debug_assert!(data.len() <= SEAL_CHUNK);
    let first = pos / 16;
    let skip = (pos % 16) as usize;
    let len = (skip + data.len()).div_ceil(16) * 16;
    for (i, block) in ks[..len].chunks_exact_mut(16).enumerate() {
        block.copy_from_slice(&u128::from(first + i as u64).to_be_bytes());
    }
    let (blocks, _) = InOutBuf::from(&mut ks[..len]).into_chunks::<U16>();
    cipher.encrypt_blocks_inout(blocks);
    for (d, k) in data.iter_mut().zip(&ks[skip..]) {
        *d ^= *k;
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
fn named(dir: &Path, private: bool) -> io::Result<NamedTempFile> {
    #[cfg(unix)]
    if !private {
        use std::os::unix::fs::PermissionsExt;
        return builder()
            .permissions(std::fs::Permissions::from_mode(0o666))
            .tempfile_in(dir);
    }
    #[cfg(not(unix))]
    let _ = private;
    builder().tempfile_in(dir)
}

/// A temp file the operating system deletes when the process ends, however it
/// ends, or `None` where that is not available here. Any failure falls back to
/// a named temp file, which reports a real problem (an unwritable folder) with
/// its own error.
#[cfg(windows)]
fn os_deleted(dir: &Path, _private: bool) -> Option<Stage> {
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
fn os_deleted(dir: &Path, private: bool) -> Option<Stage> {
    use rustix::fs::{Mode, OFlags};
    // linkat needs /proc/self/fd to give the file a name later; without it,
    // there would be no way to put the file in place.
    if !Path::new("/proc/self/fd").is_dir() {
        return None;
    }
    let mode = if private {
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
fn os_deleted(_dir: &Path, _private: bool) -> Option<Stage> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The sealed stage gives back exactly what was written, through writes of
    /// odd sizes that straddle AES blocks and seal chunks, or one write of the
    /// lot, and what sits on disk meanwhile is not the plaintext.
    #[test]
    fn sealed_stage_round_trips_and_holds_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let sizes = [
            0usize, 1, 15, 16, 17, 4095, 4096, 4097, 65_535, 65_536, 65_537, 200_000,
        ];
        for (len, piece_len) in sizes.iter().flat_map(|&l| [(l, 7_001), (l, usize::MAX)]) {
            let plain: Vec<u8> = (0..len as u32)
                .map(|i| ((i * 31) ^ (i >> 7)) as u8)
                .collect();
            let mut sealed = Sealed::new_in(dir.path()).unwrap();
            for piece in plain.chunks(piece_len) {
                sealed.write_all(piece).unwrap();
            }
            sealed.flush().unwrap();

            let mut on_disk = Vec::new();
            let file = sealed.staged.file();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_end(&mut on_disk).unwrap();
            assert_eq!(on_disk.len(), len);
            if len >= 16 {
                assert_ne!(on_disk, plain, "{len} bytes stored in the clear");
                let same = on_disk.iter().zip(&plain).filter(|(a, b)| a == b).count();
                assert!(same < len / 8 + 16, "{len}: {same} bytes stored unchanged");
            }

            let mut out = Vec::new();
            sealed.copy_out(&mut out).unwrap();
            assert_eq!(out, plain, "{len} bytes");
        }
    }

    /// Under one key, the keystream does not depend on how the bytes are split
    /// across calls: every split gives what whole chunks give.
    #[test]
    fn keystream_is_the_same_however_it_is_split() {
        let cipher = Aes256::new(&[7u8; 32].into());
        let mut ks = vec![0u8; SEAL_CHUNK + 16];
        let total = 3 * SEAL_CHUNK + 1000;
        let mut whole = vec![0u8; total];
        for (i, piece) in whole.chunks_mut(SEAL_CHUNK).enumerate() {
            apply_keystream(&cipher, (i * SEAL_CHUNK) as u64, piece, &mut ks);
        }
        for split in [1usize, 15, 16, 17, 4097, 7_001, SEAL_CHUNK - 1] {
            let mut parts = vec![0u8; total];
            for (i, piece) in parts.chunks_mut(split).enumerate() {
                apply_keystream(&cipher, (i * split) as u64, piece, &mut ks);
            }
            assert!(parts == whole, "split {split} gives a different keystream");
        }
    }

    /// Two sealed stages use different keys: the same plaintext seals to
    /// different bytes.
    #[test]
    fn sealed_stages_have_their_own_keys() {
        let dir = tempfile::tempdir().unwrap();
        let read_back = |s: &mut Sealed| {
            let mut v = Vec::new();
            let f = s.staged.file();
            f.seek(SeekFrom::Start(0)).unwrap();
            f.read_to_end(&mut v).unwrap();
            v
        };
        let mut a = Sealed::new_in(dir.path()).unwrap();
        let mut b = Sealed::new_in(dir.path()).unwrap();
        a.write_all(&[0u8; 64]).unwrap();
        b.write_all(&[0u8; 64]).unwrap();
        assert_ne!(read_back(&mut a), read_back(&mut b));
    }

    /// Dropping a stage, sealed or not, leaves its folder as it found it.
    #[test]
    fn dropped_stages_leave_nothing() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut plain = Staged::new_in(dir.path(), true).unwrap();
            plain.file().write_all(b"x").unwrap();
            let mut sealed = Sealed::new_in(dir.path()).unwrap();
            sealed.write_all(b"y").unwrap();
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
