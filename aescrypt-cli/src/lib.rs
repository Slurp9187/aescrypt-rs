// ============================================================================
// FILE: aescrypt-cli/src/lib.rs
// The `aescrypt-cli` binary's implementation. The library target exists so
// tests can drive `run` with a fixed password source; it is not a supported
// API, and everything public here is `#[doc(hidden)]`.
// ============================================================================

//! The implementation of the `aescrypt-cli` binary.
//!
//! **Not an API.** This library target exists only so the tests can drive
//! [`run`] with a fixed password source instead of a terminal. Everything
//! public here is `#[doc(hidden)]`, carries no stability promise, and may
//! change in any release. Use the `aescrypt-rs` crate to encrypt or decrypt
//! from Rust.

#![forbid(unsafe_code)]

/// Errors, exit codes, and library failures described in terms a user can act on.
mod error;
/// Staged output: temp files that are synced and renamed into place, or copied
/// to stdout, only after decryption verified.
mod output;
/// Password sources: the terminal prompt, `--password-command`,
/// `--password-file`, and generated passphrases.
mod password;
/// Ctrl-C, SIGTERM and SIGHUP handling: temp-file cleanup and terminal restore.
mod signals;

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, BufReader, BufWriter, IsTerminal, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use aescrypt_rs::{
    aliases::PasswordString,
    constants::{DEFAULT_PBKDF2_ITERATIONS, PBKDF2_MAX_ITER, PBKDF2_MIN_ITER},
    decrypt, decrypt_verified, encrypt,
};
use clap::{ArgGroup, Parser};
use secure_gate::RevealSecret;

pub use error::{CliError, ReadState};
pub use password::{
    CommandSource, FileSource, GENERATED_LEN, PASSWORD_FILE_LIMIT, PasswordSource, SHORT_PASSWORD,
    TtyPrompt, generate_passphrase,
};

/// The aescrypt-rs version this build pins with `=` in Cargo.toml.
/// `tests::lib_pin_matches` keeps the two in sync. A macro, not a `const`, so
/// `concat!` can use it.
macro_rules! lib_version {
    () => {
        "0.2.0-rc.16"
    };
}

#[doc(hidden)]
pub const LIB_VERSION: &str = lib_version!();

/// What `--version` prints after the program name, e.g.
/// `0.1.0-rc.3 (aescrypt-rs 0.2.0-rc.16)`: both versions, because a bug
/// report needs the library's too.
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (aescrypt-rs ",
    lib_version!(),
    ")"
);

/// Shown after the options with both `-h` and `--help`: what a first-time
/// user, or a script reading the help, needs before the README.
const HELP_FOOTER: &str = "\
Examples:
  aescrypt-cli -e report.pdf                       writes report.pdf.aes
  aescrypt-cli -d -o - backup.tar.aes | tar x      decrypts to stdout
  aescrypt-cli -e --password-file pw.txt -- *      non-interactive; put -- before a wildcard

Leave the encrypt prompt empty to generate a passphrase.

Exit codes: 0 success, 1 a file failed or no password was obtained, 2 usage error,
3 wrong password, 130 interrupted";

/// File-name suffix for encrypted files, as the official tool uses.
const SUFFIX: &str = "aes";

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

/// Encrypt and decrypt AES Crypt files.
///
/// Passwords are read from the terminal, --password-command or --password-file.
/// There is deliberately no option that takes a password directly.
#[derive(Debug, Parser)]
#[command(name = "aescrypt-cli", version = VERSION, about, after_help = HELP_FOOTER)]
#[command(group(ArgGroup::new("mode").required(true).args(["encrypt", "decrypt"])))]
pub struct Cli {
    /// Encrypt FILEs (output: FILE.aes)
    #[arg(short, long)]
    pub encrypt: bool,

    /// Decrypt FILEs (output: FILE without .aes)
    #[arg(short, long)]
    pub decrypt: bool,

    /// Output path; only with a single FILE. Use '-' for stdout
    #[arg(short, long, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,

    /// Overwrite existing output files (never one of this run's inputs)
    #[arg(short, long)]
    pub force: bool,

    /// PBKDF2 iterations when encrypting [default: 600000]
    #[arg(long, value_name = "N")]
    pub iterations: Option<u32>,

    /// Read the password from this command's stdout instead of prompting
    #[arg(long, value_name = "CMD")]
    pub password_command: Option<String>,

    /// Read the password from this file (minus one trailing newline) instead
    /// of prompting
    #[arg(long, value_name = "PATH", conflicts_with = "password_command")]
    pub password_file: Option<PathBuf>,

    /// Files to process. Use '-' for stdin (requires -o)
    #[arg(required = true, value_name = "FILE")]
    pub files: Vec<PathBuf>,
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

/// Validated options.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct Opts {
    pub mode: Mode,
    pub files: Vec<PathBuf>,
    pub output: Option<PathBuf>,
    pub force: bool,
    pub iterations: u32,
    /// Read before any output is written, so no output may replace it.
    pub password_file: Option<PathBuf>,
}

impl TryFrom<&Cli> for Opts {
    type Error = CliError;

    fn try_from(cli: &Cli) -> Result<Self, CliError> {
        let mode = if cli.encrypt {
            Mode::Encrypt
        } else {
            Mode::Decrypt
        };
        if cli.output.is_some() && cli.files.len() > 1 {
            return Err(CliError::Usage(
                "-o can only be used with a single FILE".into(),
            ));
        }
        let stdin_inputs = cli.files.iter().filter(|f| is_dash(f)).count();
        if stdin_inputs > 0 && cli.output.is_none() {
            return Err(CliError::Usage(
                "reading from stdin ('-') requires -o".into(),
            ));
        }
        if mode == Mode::Decrypt && cli.iterations.is_some() {
            return Err(CliError::Usage("--iterations only applies to -e".into()));
        }
        let iterations = cli.iterations.unwrap_or(DEFAULT_PBKDF2_ITERATIONS);
        if !(PBKDF2_MIN_ITER..=PBKDF2_MAX_ITER).contains(&iterations) {
            return Err(CliError::Usage(format!(
                "--iterations must be between {PBKDF2_MIN_ITER} and {PBKDF2_MAX_ITER}"
            )));
        }
        Ok(Opts {
            mode,
            files: cli.files.clone(),
            output: cli.output.clone(),
            force: cli.force,
            iterations,
            password_file: cli.password_file.clone(),
        })
    }
}

/// The process's standard streams, injectable for tests.
#[doc(hidden)]
pub struct Streams<'a> {
    pub stdin: &'a mut dyn Read,
    pub stdout: &'a mut dyn Write,
    pub stdout_is_terminal: bool,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// `main` for the binary. Returns the process exit code.
#[doc(hidden)]
pub fn main_entry() -> i32 {
    let cli = Cli::parse();
    let opts = match Opts::try_from(&cli) {
        Ok(o) => o,
        Err(e) => return report_fatal(&e),
    };
    signals::install();

    // clap rejects --password-command together with --password-file.
    let source: Box<dyn PasswordSource> = match (cli.password_command, cli.password_file) {
        (Some(command), _) => Box::new(CommandSource { command }),
        (None, Some(path)) => Box::new(FileSource { path }),
        (None, None) => Box::new(TtyPrompt),
    };

    let stdout = io::stdout();
    let stdout_is_terminal = stdout.is_terminal();
    let mut stdin = io::stdin().lock();
    let mut stdout = stdout.lock();
    let mut streams = Streams {
        stdin: &mut stdin,
        stdout: &mut stdout,
        stdout_is_terminal,
    };
    match run(&opts, source.as_ref(), &mut streams) {
        Ok(failures) => {
            for e in &failures {
                say(&format!("aescrypt-cli: {e}"));
            }
            files_exit_code(&failures)
        }
        Err(e) => report_fatal(&e),
    }
}

/// Some file failed.
const EXIT_FAILED: i32 = 1;
/// Every failure was a wrong password, so retrying with another one may work.
const EXIT_WRONG_PASSWORD: i32 = 3;

/// Exit code for a run that got as far as the files: 0 if all succeeded, 3 if
/// every failure was a wrong password, otherwise 1.
fn files_exit_code(failures: &[CliError]) -> i32 {
    if failures.is_empty() {
        0
    } else if failures.iter().all(CliError::is_wrong_password) {
        EXIT_WRONG_PASSWORD
    } else {
        EXIT_FAILED
    }
}

/// Prints an error that ends the run and returns its exit code.
fn report_fatal(e: &CliError) -> i32 {
    say(&format!("aescrypt-cli: {e}"));
    e.exit_code()
}

/// Writes a line to stderr. Unlike `eprintln!`, a failed write (terminal hung
/// up, stderr on a full disk) is ignored instead of panicking with exit 101:
/// the exit code still reports the failure.
pub(crate) fn say(line: &str) {
    let _ = writeln!(io::stderr(), "{line}");
}

/// Processes every file. A failure on one file does not stop the others.
///
/// Returns `Err` only for problems that end the whole run (usage, password);
/// per-file failures come back in the `Ok` list.
#[doc(hidden)]
pub fn run(
    opts: &Opts,
    source: &dyn PasswordSource,
    streams: &mut Streams<'_>,
) -> Result<Vec<CliError>, CliError> {
    // Everything that can be refused is refused before the prompt, so nobody
    // types a password only to be told the output already exists.
    let mut failures = Vec::new();
    let mut jobs: Vec<Job> = Vec::new();
    for input in &opts.files {
        match plan(opts, input, streams.stdout_is_terminal)
            .and_then(|job| check_batch(&job, &jobs, opts).map(|()| job))
        {
            Ok(job) => jobs.push(job),
            Err(e) => failures.push(e),
        }
    }
    if jobs.is_empty() {
        return Ok(failures);
    }

    let password = source.password(opts.mode)?;
    for job in &jobs {
        if let Err(e) = execute(opts, job, &password, streams) {
            failures.push(e);
        }
    }
    Ok(failures)
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// Where one job reads from.
#[derive(Debug)]
enum Source {
    /// Standard input, given as `-`.
    Stdin,
    /// A file that existed and was not a directory when the job was planned.
    File(PathBuf),
}

/// Where one job writes to.
#[derive(Debug)]
enum Sink {
    /// Standard output, given as `-o -`.
    Stdout,
    /// A file path; written through a staged temp file and renamed into place.
    File(PathBuf),
}

/// One input to process and where its output goes, decided before any
/// password is asked for.
#[derive(Debug)]
struct Job {
    /// The input.
    source: Source,
    /// The output.
    sink: Sink,
}

/// Whether a path argument is `-`, meaning stdin or stdout.
fn is_dash(p: &Path) -> bool {
    p.as_os_str() == OsStr::new("-")
}

/// Turns one input into a [`Job`], refusing anything that can be refused
/// before the password prompt: a missing input or a directory, an output that
/// exists without `--force`, an output that is the input, ciphertext to a
/// terminal, and a name with no `.aes` to strip.
fn plan(opts: &Opts, input: &Path, stdout_is_terminal: bool) -> Result<Job, CliError> {
    let source = if is_dash(input) {
        Source::Stdin
    } else {
        let meta = std::fs::metadata(input).map_err(|e| CliError::io(input, e))?;
        if meta.is_dir() {
            return Err(CliError::refused(input, "is a directory"));
        }
        Source::File(input.to_path_buf())
    };

    let sink = match &opts.output {
        Some(o) if is_dash(o) => Sink::Stdout,
        Some(o) => Sink::File(o.clone()),
        None => Sink::File(default_output(opts.mode, input)?),
    };

    match &sink {
        Sink::Stdout => {
            if opts.mode == Mode::Encrypt && stdout_is_terminal {
                return Err(CliError::refused(
                    input,
                    "refusing to write ciphertext to a terminal; use -o or redirect stdout",
                ));
            }
        }
        Sink::File(out) => {
            if let Ok(meta) = std::fs::metadata(out) {
                if meta.is_dir() {
                    return Err(CliError::refused(out, "output is a directory"));
                }
                if let Source::File(inp) = &source {
                    // Device + inode (file index on Windows): catches symlinks
                    // and hard links that a path comparison would miss.
                    if same_file::is_same_file(inp, out).unwrap_or(false) {
                        return Err(CliError::refused(out, "input and output are the same file"));
                    }
                }
                if !opts.force {
                    return Err(CliError::refused(
                        out,
                        "already exists (use --force to overwrite)",
                    ));
                }
            }
        }
    }
    Ok(Job { source, sink })
}

/// Refuses a job whose output would replace another file in the same run:
/// any input (jobs run in order, so a later input would be read after it was
/// overwritten, and an earlier one is still the user's file), or the output of
/// a job already accepted, or the --password-file. `--force` does not override
/// this; it is about files from before the run, not ones the run itself reads
/// or writes.
fn check_batch(job: &Job, accepted: &[Job], opts: &Opts) -> Result<(), CliError> {
    let Sink::File(out) = &job.sink else {
        return Ok(());
    };
    if let Some(pw) = &opts.password_file {
        if same_file::is_same_file(pw, out).unwrap_or(false) {
            return Err(CliError::refused(out, "is the --password-file"));
        }
    }
    let is_input = opts
        .files
        .iter()
        .filter(|i| !is_dash(i))
        .any(|i| same_file::is_same_file(i, out).unwrap_or(false));
    if is_input {
        return Err(CliError::refused(out, "is also one of the input files"));
    }
    let taken = accepted.iter().any(|j| match &j.sink {
        Sink::File(o) => same_destination(o, out),
        Sink::Stdout => false,
    });
    if taken {
        return Err(CliError::refused(
            out,
            "is already the output of another file",
        ));
    }
    Ok(())
}

/// Whether two output paths name the same file. Outputs usually don't exist
/// yet, so besides device + inode this compares the resolved parent directory
/// and the file name.
fn same_destination(a: &Path, b: &Path) -> bool {
    if same_file::is_same_file(a, b).unwrap_or(false) {
        return true;
    }
    let key = |p: &Path| {
        let parent = match p.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        Some((parent.canonicalize().ok()?, p.file_name()?.to_owned()))
    };
    matches!((key(a), key(b)), (Some(x), Some(y)) if x == y)
}

/// `x` -> `x.aes` when encrypting; `x.aes` -> `x` when decrypting.
fn default_output(mode: Mode, input: &Path) -> Result<PathBuf, CliError> {
    match mode {
        Mode::Encrypt => {
            let mut s: OsString = input.as_os_str().to_owned();
            s.push(".");
            s.push(SUFFIX);
            Ok(PathBuf::from(s))
        }
        Mode::Decrypt => {
            // `Path::extension` is None for a file named just `.aes` (a hidden
            // stem, not a suffix), so name that case rather than claim the
            // suffix is missing.
            if input
                .file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case(".aes"))
            {
                return Err(CliError::refused(
                    input,
                    "has no name before .aes; use -o to name the output",
                ));
            }
            let is_aes = input
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case(SUFFIX));
            if is_aes {
                Ok(input.with_extension(""))
            } else {
                Err(CliError::refused(
                    input,
                    "does not end in .aes; use -o to name the output",
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// Runs one planned job. A file output is staged next to its destination and
/// renamed into place after the library call succeeds; decrypting to stdout is
/// staged in the temp directory and copied out only after verification;
/// encrypting to stdout streams directly.
fn execute(
    opts: &Opts,
    job: &Job,
    password: &PasswordString,
    streams: &mut Streams<'_>,
) -> Result<(), CliError> {
    let label: PathBuf = match &job.source {
        Source::Stdin => PathBuf::from("<stdin>"),
        Source::File(p) => p.clone(),
    };
    let mut input = match &job.source {
        Source::Stdin => Input::Stdin(VersionTap::new(&mut *streams.stdin)),
        Source::File(p) => Input::File(VersionTap::new(BufReader::new(
            File::open(p).map_err(|e| CliError::io(p, e))?,
        ))),
    };
    let mut run_lib = |w: &mut dyn Write| crypt(opts, password, &label, &mut input, w);

    match (&job.sink, opts.mode) {
        // Ciphertext is not sensitive: stream it straight out.
        (Sink::Stdout, Mode::Encrypt) => {
            let mut w = BufWriter::new(&mut *streams.stdout);
            run_lib(&mut w)?;
            w.flush().map_err(|e| CliError::io("<stdout>", e))
        }
        // Plaintext reaches stdout only after it has been authenticated.
        (Sink::Stdout, Mode::Decrypt) => {
            let mut staged = output::Staged::new_in(&std::env::temp_dir(), true)?;
            {
                let mut w = staged.writer();
                run_lib(&mut w)?;
                w.flush().map_err(|e| CliError::io(&label, e))?;
            }
            staged.copy_to(&mut *streams.stdout)
        }
        (Sink::File(dest), mode) => {
            let mut staged =
                output::Staged::new_in(output::parent_dir(dest), mode == Mode::Decrypt)?;
            {
                let mut w = staged.writer();
                run_lib(&mut w)?;
                w.flush().map_err(|e| CliError::io(dest, e))?;
            }
            staged.persist(dest, opts.force)
        }
    }
}

/// One job's input, wrapped so failures can name the format version.
enum Input<'a> {
    /// A file. It can seek, so decryption checks the HMAC before writing any
    /// plaintext (`decrypt_verified`, which reads the file twice).
    File(VersionTap<BufReader<File>>),
    /// Standard input. It cannot seek, so decryption is one pass and writes
    /// plaintext before the HMAC is checked; the caller stages the output and
    /// discards it on error.
    Stdin(VersionTap<&'a mut dyn Read>),
}

impl Input<'_> {
    /// What had been read when the library call returned.
    fn read_state(&self) -> error::ReadState {
        let (version, bytes) = match self {
            Input::File(t) => (t.version, t.pos),
            Input::Stdin(t) => (t.version, t.pos),
        };
        error::ReadState { version, bytes }
    }
}

/// Runs the library call. Errors carry the file's format version, because
/// what a failure means depends on it (see `error::describe`).
fn crypt(
    opts: &Opts,
    password: &PasswordString,
    label: &Path,
    input: &mut Input<'_>,
    w: &mut dyn Write,
) -> Result<(), CliError> {
    password
        .with_secret(|pw| match (opts.mode, &mut *input) {
            (Mode::Encrypt, Input::File(t)) => encrypt(t, w, pw, opts.iterations),
            (Mode::Encrypt, Input::Stdin(t)) => encrypt(t, w, pw, opts.iterations),
            (Mode::Decrypt, Input::File(t)) => decrypt_verified(t, w, pw).map(drop),
            (Mode::Decrypt, Input::Stdin(t)) => decrypt(t, w, pw),
        })
        .map_err(|source| CliError::Crypto {
            path: label.to_path_buf(),
            // Only a ciphertext has a format version; byte 3 of a plaintext
            // being encrypted means nothing.
            decrypt: (opts.mode == Mode::Decrypt).then(|| input.read_state()),
            source,
        })
}

/// Passes reads (and, for a file, seeks) through, counting bytes read and
/// remembering byte 3 of the stream: the AES Crypt format version (`"AES"`
/// then the version byte).
struct VersionTap<R> {
    /// The real input.
    inner: R,
    /// Bytes read so far, across both passes of a verified decrypt: 0 means
    /// the input was empty.
    pos: u64,
    /// Byte 3 of the input once it has been read. Caught while the header is
    /// read, before `decrypt_verified` seeks back for its second pass.
    version: Option<u8>,
}

impl<R> VersionTap<R> {
    /// Wraps `inner`, with nothing read yet.
    fn new(inner: R) -> Self {
        Self {
            inner,
            pos: 0,
            version: None,
        }
    }
}

impl<R: Read> Read for VersionTap<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if self.version.is_none() && self.pos <= 3 && self.pos + n as u64 > 3 {
            self.version = Some(buf[(3 - self.pos) as usize]);
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Seek> Seek for VersionTap<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.inner.seek(to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `=` pin on aescrypt-rs in Cargo.toml must be `LIB_VERSION`.
    #[test]
    fn lib_pin_matches() {
        // Two shapes: the inline table in the repo's Cargo.toml, and the
        // `[dependencies.aescrypt-rs]` table `cargo package` rewrites it into,
        // which is what a published crate's tests read.
        let manifest = include_str!("../Cargo.toml");
        let mut lines = manifest.lines();
        let line = lines
            .by_ref()
            .find(|l| l.starts_with("aescrypt-rs = ") || l.trim() == "[dependencies.aescrypt-rs]")
            .expect("aescrypt-rs dependency");
        let line = if line.starts_with('[') {
            lines
                .take_while(|l| !l.starts_with('['))
                .find(|l| l.starts_with("version = "))
                .expect("version under [dependencies.aescrypt-rs]")
        } else {
            line
        };
        assert!(
            line.contains(&format!("version = \"={LIB_VERSION}\"")),
            "Cargo.toml pins {line}, LIB_VERSION is {LIB_VERSION}"
        );
        assert!(VERSION.ends_with(&format!("(aescrypt-rs {LIB_VERSION})")));
    }

    /// The `--help` text states the default as a literal (a doc comment can't
    /// name a constant), so it must match the library's real default. Fails
    /// when a library bump changes `DEFAULT_PBKDF2_ITERATIONS`.
    #[test]
    fn help_shows_default_iterations() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains(&format!("[default: {DEFAULT_PBKDF2_ITERATIONS}]")),
            "{help}"
        );
    }

    #[test]
    fn default_names() {
        let enc = default_output(Mode::Encrypt, Path::new("dir/a.txt")).unwrap();
        assert_eq!(enc, Path::new("dir/a.txt.aes"));
        let dec = default_output(Mode::Decrypt, Path::new("dir/a.txt.AES")).unwrap();
        assert_eq!(dec, Path::new("dir/a.txt"));
        assert!(default_output(Mode::Decrypt, Path::new("a.txt")).is_err());
        assert!(default_output(Mode::Decrypt, Path::new(".aes")).is_err());
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    // -- Which library call decrypt uses (#59) -------------------------------
    //
    // Staging hides the difference at the CLI boundary: either way a failed
    // decrypt leaves no output. These tests look underneath, at the bytes the
    // library call writes into the stage.

    /// Counts what is written and keeps nothing.
    #[derive(Default)]
    struct Count(usize);

    impl Write for Count {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn decrypt_opts() -> Opts {
        Opts {
            mode: Mode::Decrypt,
            files: Vec::new(),
            output: None,
            force: false,
            iterations: 5,
            password_file: None,
        }
    }

    /// Tampered files of every version available, each paired with its
    /// version and password: a fresh v3 file, and the largest official v0–v2
    /// vector when the repository's test data is present (it is not in the
    /// published tarball). The last ciphertext byte is flipped.
    fn tampered_files() -> Vec<(u8, &'static str, Vec<u8>)> {
        let mut files = Vec::new();
        let mut v3 = Vec::new();
        encrypt(io::Cursor::new(vec![7u8; 100_000]), &mut v3, "pw", 5).unwrap();
        files.push((3, "pw", v3));

        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/test_data/aes_test_files");
        for version in 0..=2u8 {
            let Ok(entries) = std::fs::read_dir(dir.join(format!("v{version}"))) else {
                eprintln!("skipped v{version}: test data not present");
                continue;
            };
            let largest = entries
                .map(|e| std::fs::read(e.unwrap().path()).unwrap())
                .max_by_key(Vec::len)
                .unwrap();
            files.push((version, "Hello", largest));
        }

        for (version, _, bytes) in &mut files {
            let trailer = if matches!(*version, 1 | 2) { 33 } else { 32 };
            let last_ciphertext_byte = bytes.len() - trailer - 1;
            bytes[last_ciphertext_byte] ^= 1;
        }
        files
    }

    /// A file input is decrypted with `decrypt_verified`: a tampered file
    /// writes nothing at all, not even into the stage.
    #[test]
    fn tampered_file_input_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        for (version, pw, bytes) in tampered_files() {
            let path = dir.path().join(format!("v{version}.aes"));
            std::fs::write(&path, &bytes).unwrap();
            let mut input =
                Input::File(VersionTap::new(BufReader::new(File::open(&path).unwrap())));
            let mut out = Count::default();
            let password = PasswordString::new(pw.to_string());

            let err = crypt(&decrypt_opts(), &password, &path, &mut input, &mut out)
                .expect_err("tampered file decrypted");
            assert!(
                err.to_string().contains("damaged or was tampered with"),
                "v{version}: {err}"
            );
            assert_eq!(
                out.0, 0,
                "v{version}: plaintext written before the HMAC check"
            );
            assert_eq!(input.read_state().version, Some(version));
        }
    }

    /// Standard input cannot seek, so it stays on the one-pass `decrypt`,
    /// which writes plaintext before the check. That is what staging is for;
    /// this pins the split.
    #[test]
    fn tampered_stdin_input_is_one_pass() {
        let (_, pw, bytes) = tampered_files().swap_remove(0);
        let mut stdin = io::Cursor::new(bytes);
        let mut input = Input::Stdin(VersionTap::new(&mut stdin));
        let mut out = Count::default();
        let password = PasswordString::new(pw.to_string());

        assert!(
            crypt(
                &decrypt_opts(),
                &password,
                Path::new("<stdin>"),
                &mut input,
                &mut out
            )
            .is_err()
        );
        assert!(out.0 > 0, "stdin unexpectedly verified first");
    }

    /// A clean file input decrypts to the original through the verified path.
    #[test]
    fn clean_file_input_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.aes");
        let mut cipher = Vec::new();
        encrypt(io::Cursor::new(b"hello, verified"), &mut cipher, "pw", 5).unwrap();
        std::fs::write(&path, cipher).unwrap();

        let mut input = Input::File(VersionTap::new(BufReader::new(File::open(&path).unwrap())));
        let mut out = Vec::new();
        let password = PasswordString::new("pw".to_string());
        crypt(&decrypt_opts(), &password, &path, &mut input, &mut out).unwrap();
        assert_eq!(out, b"hello, verified");
    }
}
