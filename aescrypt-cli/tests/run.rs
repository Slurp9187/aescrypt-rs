//! `tests/run.rs`
//! Drives `aescrypt_cli::run` in-process with a fixed password, covering the
//! file-handling rules. Binary-level behavior is in `tests/binary.rs`.

// Test crate: helpers and fixtures are explained by the tests that use them.
#![allow(clippy::missing_docs_in_private_items)]

use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use aescrypt_cli::{Cli, CliError, Mode, Opts, PasswordSource, Streams, run};
use aescrypt_rs::aliases::PasswordString;
use clap::Parser;

const PW: &str = "correct horse battery staple";

struct Fixed(&'static str);

impl PasswordSource for Fixed {
    fn password(&self, _mode: Mode) -> Result<PasswordString, CliError> {
        Ok(PasswordString::new(self.0.to_string()))
    }
}

/// Parses `args` as the binary would and runs them with password `pw`.
/// Returns (fatal error, per-file failures, stdout bytes).
fn cli(
    args: &[&str],
    pw: &'static str,
    stdin: &[u8],
) -> (Option<CliError>, Vec<CliError>, Vec<u8>) {
    let mut argv = vec!["aescrypt-cli"];
    argv.extend_from_slice(args);
    let parsed = Cli::try_parse_from(argv).expect("valid command line");
    let opts = match Opts::try_from(&parsed) {
        Ok(o) => o,
        Err(e) => return (Some(e), Vec::new(), Vec::new()),
    };
    run_opts(&opts, pw, stdin)
}

fn run_opts(
    opts: &Opts,
    pw: &'static str,
    stdin: &[u8],
) -> (Option<CliError>, Vec<CliError>, Vec<u8>) {
    let mut input = Cursor::new(stdin.to_vec());
    let mut out = Vec::new();
    let mut streams = Streams {
        stdin: &mut input,
        stdout: &mut out,
        stdout_is_terminal: false,
    };
    match run(opts, &Fixed(pw), &mut streams) {
        Ok(failures) => (None, failures, out),
        Err(e) => (Some(e), Vec::new(), out),
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Names in `dir`, sorted, so leftover temp files show up in assertions.
fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn ok(r: &(Option<CliError>, Vec<CliError>, Vec<u8>)) {
    assert!(r.0.is_none(), "fatal: {:?}", r.0);
    assert!(r.1.is_empty(), "failures: {:?}", r.1);
}

fn fast() -> [&'static str; 2] {
    ["--iterations", "5"]
}

fn encrypt_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let plain = dir.join(name);
    fs::write(&plain, content).unwrap();
    let [a, b] = fast();
    ok(&cli(&["-e", a, b, s(&plain)], PW, b""));
    fs::remove_file(&plain).unwrap();
    dir.join(format!("{name}.aes"))
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_default_names() {
    let dir = tempfile::tempdir().unwrap();
    let enc = encrypt_file(dir.path(), "a.txt", b"hello world");
    assert_eq!(listing(dir.path()), ["a.txt.aes"]);

    ok(&cli(&["-d", s(&enc)], PW, b""));
    assert_eq!(fs::read(dir.path().join("a.txt")).unwrap(), b"hello world");
}

#[test]
fn several_files_one_password() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    fs::write(&a, b"A").unwrap();
    fs::write(&b, b"B").unwrap();
    let [x, y] = fast();
    ok(&cli(&["-e", x, y, s(&a), s(&b)], PW, b""));
    fs::remove_file(&a).unwrap();
    fs::remove_file(&b).unwrap();
    ok(&cli(
        &[
            "-d",
            s(&dir.path().join("a.aes")),
            s(&dir.path().join("b.aes")),
        ],
        PW,
        b"",
    ));
    assert_eq!(fs::read(&a).unwrap(), b"A");
    assert_eq!(fs::read(&b).unwrap(), b"B");
}

#[test]
fn one_bad_file_does_not_stop_the_others() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good");
    fs::write(&good, b"ok").unwrap();
    let missing = dir.path().join("missing");
    let [x, y] = fast();
    let r = cli(&["-e", x, y, s(&missing), s(&good)], PW, b"");
    assert!(r.0.is_none());
    assert_eq!(r.1.len(), 1);
    assert!(dir.path().join("good.aes").exists());
}

#[test]
fn stdin_to_file_and_file_to_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let enc = dir.path().join("x.aes");
    let [x, y] = fast();
    ok(&cli(&["-e", x, y, "-o", s(&enc), "-"], PW, b"from stdin"));

    let r = cli(&["-d", "-o", "-", s(&enc)], PW, b"");
    ok(&r);
    assert_eq!(r.2, b"from stdin");
}

#[test]
fn encrypt_to_stdout_then_decrypt_from_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("p");
    fs::write(&plain, b"piped").unwrap();
    let [x, y] = fast();
    let enc = cli(&["-e", x, y, "-o", "-", s(&plain)], PW, b"");
    ok(&enc);
    assert_eq!(&enc.2[..3], b"AES");

    let dec = cli(&["-d", "-o", "-", "-"], PW, &enc.2);
    ok(&dec);
    assert_eq!(dec.2, b"piped");
}

#[cfg(unix)]
#[test]
fn non_utf8_file_name() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    let dir = tempfile::tempdir().unwrap();
    let name = OsStr::from_bytes(b"bad-\xff-name");
    let plain = dir.path().join(name);
    match fs::write(&plain, b"bytes") {
        Ok(()) => {}
        // APFS (macOS) only stores UTF-8 names; nothing to test there.
        Err(e) if e.raw_os_error() == Some(libc::EILSEQ) => return,
        Err(e) => panic!("{e}"),
    }

    let opts = |mode, file: PathBuf| Opts {
        mode,
        files: vec![file],
        output: None,
        force: false,
        iterations: 5,
        password_file: None,
    };
    ok(&run_opts(&opts(Mode::Encrypt, plain.clone()), PW, b""));
    fs::remove_file(&plain).unwrap();

    let mut enc = plain.clone().into_os_string();
    enc.push(".aes");
    ok(&run_opts(&opts(Mode::Decrypt, PathBuf::from(enc)), PW, b""));
    assert_eq!(fs::read(&plain).unwrap(), b"bytes");
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[test]
fn refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let enc = encrypt_file(dir.path(), "a.txt", b"new");
    let dest = dir.path().join("a.txt");
    fs::write(&dest, b"precious").unwrap();

    let r = cli(&["-d", s(&enc)], PW, b"");
    assert_eq!(r.1.len(), 1);
    assert!(r.1[0].to_string().contains("already exists"));
    assert_eq!(fs::read(&dest).unwrap(), b"precious");

    ok(&cli(&["-d", "--force", s(&enc)], PW, b""));
    assert_eq!(fs::read(&dest).unwrap(), b"new");
}

#[cfg(unix)]
#[test]
fn refuses_same_file_through_links() {
    let dir = tempfile::tempdir().unwrap();
    let enc = encrypt_file(dir.path(), "a", b"data");
    let original = fs::read(&enc).unwrap();

    let hard = dir.path().join("hard");
    fs::hard_link(&enc, &hard).unwrap();
    let sym = dir.path().join("sym");
    std::os::unix::fs::symlink(&enc, &sym).unwrap();

    for link in [&enc, &hard, &sym] {
        let r = cli(&["-d", "--force", "-o", s(link), s(&enc)], PW, b"");
        assert_eq!(r.1.len(), 1, "{link:?}");
        assert!(r.1[0].to_string().contains("same file"), "{}", r.1[0]);
    }
    assert_eq!(fs::read(&enc).unwrap(), original);
}

/// One job's output must never replace another file in the same run, with or
/// without `--force`, whichever order the files come in.
#[test]
fn refuses_output_that_is_another_input() {
    let dir = tempfile::tempdir().unwrap();
    let [x, y] = fast();

    // Encrypt: `note` -> `note.aes`, which is also an input.
    let note = dir.path().join("note");
    let note_aes = dir.path().join("note.aes");
    for order in [[&note, &note_aes], [&note_aes, &note]] {
        fs::write(&note, b"new plaintext").unwrap();
        fs::write(&note_aes, b"only copy").unwrap();
        let r = cli(&["-e", "--force", x, y, s(order[0]), s(order[1])], PW, b"");
        assert_eq!(r.1.len(), 1, "{order:?}: {:?}", r.1);
        assert!(
            r.1[0].to_string().contains("one of the input files"),
            "{}",
            r.1[0]
        );
        assert_eq!(fs::read(&note_aes).unwrap(), b"only copy", "{order:?}");
        let _ = fs::remove_file(dir.path().join("note.aes.aes"));
    }

    // Decrypt: `b.aes.aes` -> `b.aes`, an unrelated ciphertext and an input.
    let beta = encrypt_file(dir.path(), "b", b"BETA");
    let beta_bytes = fs::read(&beta).unwrap();
    let alpha = dir.path().join("b.aes.aes");
    fs::write(
        &alpha,
        fs::read(encrypt_file(dir.path(), "a", b"ALPHA")).unwrap(),
    )
    .unwrap();
    for order in [[&alpha, &beta], [&beta, &alpha]] {
        let r = cli(&["-d", "--force", s(order[0]), s(order[1])], PW, b"");
        assert!(
            r.1.iter()
                .any(|e| e.to_string().contains("one of the input files")),
            "{order:?}: {:?}",
            r.1
        );
        assert_eq!(fs::read(&beta).unwrap(), beta_bytes, "{order:?}");
    }
}

#[test]
fn refuses_two_jobs_with_one_output() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    fs::write(&a, b"A").unwrap();
    let [x, y] = fast();
    let r = cli(&["-e", "--force", x, y, s(&a), s(&a)], PW, b"");
    assert_eq!(r.1.len(), 1, "{:?}", r.1);
    assert!(
        r.1[0].to_string().contains("output of another file"),
        "{}",
        r.1[0]
    );
    assert!(dir.path().join("a.aes").exists());
}

#[test]
fn refuses_directory_input() {
    let dir = tempfile::tempdir().unwrap();
    let r = cli(&["-e", s(dir.path())], PW, b"");
    assert!(r.1[0].to_string().contains("is a directory"));
}

#[test]
fn file_named_just_aes() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join(".aes");
    fs::write(&f, b"x").unwrap();
    let r = cli(&["-d", s(&f)], PW, b"");
    assert!(
        r.1[0].to_string().contains("no name before .aes"),
        "{}",
        r.1[0]
    );
}

#[test]
fn decrypt_needs_aes_suffix_or_output() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("plain.bin");
    fs::write(&f, b"x").unwrap();
    let r = cli(&["-d", s(&f)], PW, b"");
    assert!(r.1[0].to_string().contains("does not end in .aes"));
}

#[test]
fn refuses_ciphertext_to_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("p");
    fs::write(&f, b"x").unwrap();
    let parsed = Cli::try_parse_from(["aescrypt-cli", "-e", "-o", "-", s(&f)]).unwrap();
    let opts = Opts::try_from(&parsed).unwrap();
    let mut input = Cursor::new(Vec::new());
    let mut out = Vec::new();
    let mut streams = Streams {
        stdin: &mut input,
        stdout: &mut out,
        stdout_is_terminal: true,
    };
    let failures = run(&opts, &Fixed(PW), &mut streams).unwrap();
    assert!(failures[0].to_string().contains("terminal"));
    assert!(out.is_empty());
}

#[test]
fn usage_errors() {
    let cases: &[&[&str]] = &[
        &["-e", "-o", "x", "a", "b"], // -o with several files
        &["-e", "-"],                 // stdin without -o
        &["-d", "--iterations", "9", "a.aes"],
        &["-e", "--iterations", "0", "a"],
        &["-e", "--iterations", "5000001", "a"],
    ];
    for args in cases {
        let r = cli(args, PW, b"");
        let e = r.0.unwrap_or_else(|| panic!("{args:?} accepted"));
        assert_eq!(e.exit_code(), 2, "{args:?}: {e}");
    }
}

#[test]
fn nothing_is_prompted_when_every_file_is_refused() {
    struct Panics;
    impl PasswordSource for Panics {
        fn password(&self, _: Mode) -> Result<PasswordString, CliError> {
            panic!("prompted although nothing could be processed");
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let parsed =
        Cli::try_parse_from(["aescrypt-cli", "-e", s(&dir.path().join("missing"))]).unwrap();
    let opts = Opts::try_from(&parsed).unwrap();
    let mut input = Cursor::new(Vec::new());
    let mut out = Vec::new();
    let mut streams = Streams {
        stdin: &mut input,
        stdout: &mut out,
        stdout_is_terminal: false,
    };
    assert_eq!(run(&opts, &Panics, &mut streams).unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Failures leave nothing behind
// ---------------------------------------------------------------------------

#[test]
fn wrong_password_leaves_no_output() {
    let dir = tempfile::tempdir().unwrap();
    let enc = encrypt_file(dir.path(), "a.txt", &[7u8; 10_000]);
    let r = cli(&["-d", s(&enc)], "not the password", b"");
    assert_eq!(r.1.len(), 1);
    assert!(r.1[0].to_string().contains("wrong password"), "{}", r.1[0]);
    assert_eq!(listing(dir.path()), ["a.txt.aes"]);
}

#[test]
fn tampered_file_leaves_no_output() {
    let dir = tempfile::tempdir().unwrap();
    // Large enough that the library has streamed plaintext before the HMAC.
    let enc = encrypt_file(dir.path(), "a.txt", &[7u8; 100_000]);
    let mut bytes = fs::read(&enc).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&enc, &bytes).unwrap();

    let r = cli(&["-d", s(&enc)], PW, b"");
    assert_eq!(r.1.len(), 1);
    assert_eq!(listing(dir.path()), ["a.txt.aes"]);

    let r = cli(&["-d", "-o", "-", s(&enc)], PW, b"");
    assert_eq!(r.1.len(), 1);
    assert!(
        r.2.is_empty(),
        "{} unverified bytes reached stdout",
        r.2.len()
    );

    // The same file through stdin (#72): its ciphertext is staged and checked
    // before anything is written, to a file or to stdout.
    let out = dir.path().join("from-stdin");
    let r = cli(&["-d", "-o", s(&out), "-"], PW, &bytes);
    assert_eq!(r.1.len(), 1);
    assert_eq!(listing(dir.path()), ["a.txt.aes"]);

    let r = cli(&["-d", "-o", "-", "-"], PW, &bytes);
    assert_eq!(r.1.len(), 1);
    assert!(
        r.2.is_empty(),
        "{} unverified bytes from stdin reached stdout",
        r.2.len()
    );
}

/// A clean stdin decrypts to stdout and to a file through the staged,
/// verify-first path (#72), and leaves no stage behind.
#[test]
fn stdin_decrypts_verified_to_stdout_and_file() {
    let dir = tempfile::tempdir().unwrap();
    let enc = encrypt_file(dir.path(), "a.txt", &[9u8; 70_000]);
    let cipher = fs::read(&enc).unwrap();

    let r = cli(&["-d", "-o", "-", "-"], PW, &cipher);
    ok(&r);
    assert_eq!(r.2, vec![9u8; 70_000]);

    let out = dir.path().join("plain");
    ok(&cli(&["-d", "-o", s(&out), "-"], PW, &cipher));
    assert_eq!(fs::read(&out).unwrap(), vec![9u8; 70_000]);
    assert_eq!(listing(dir.path()), ["a.txt.aes", "plain"]);
}

/// The official v0–v2 vectors with their last ciphertext byte flipped, and a
/// v0 file with the wrong password (v0 has no session block, so that fails
/// only at the payload HMAC): no target and no temp file is left in the
/// folder, and nothing reaches stdout.
#[test]
fn tampered_legacy_files_leave_no_output() {
    let Some(data) = vector_dir() else {
        eprintln!("skipped: ../tests/test_data not present (published tarball)");
        return;
    };
    for version in 0..=2u8 {
        let (_, mut cipher) = vectors(&data, version).pop().unwrap();
        let trailer = if version == 0 { 32 } else { 33 };
        let at = cipher.len() - trailer - 1;
        cipher[at] ^= 1;

        let dir = tempfile::tempdir().unwrap();
        let enc = dir.path().join("f.aes");
        fs::write(&enc, &cipher).unwrap();
        let r = cli(&["-d", s(&enc)], "Hello", b"");
        assert_eq!(r.1.len(), 1, "v{version}: {:?}", r.1);
        assert_eq!(listing(dir.path()), ["f.aes"], "v{version}");

        let r = cli(&["-d", "-o", "-", s(&enc)], "Hello", b"");
        assert_eq!(r.1.len(), 1, "v{version}");
        assert!(r.2.is_empty(), "v{version}: bytes reached stdout");
    }

    let (_, v0) = vectors(&data, 0).pop().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let enc = dir.path().join("f.aes");
    fs::write(&enc, &v0).unwrap();
    let r = cli(&["-d", s(&enc)], "not the password", b"");
    assert_eq!(r.1.len(), 1);
    assert!(r.1[0].to_string().contains("wrong password"), "{}", r.1[0]);
    assert_eq!(listing(dir.path()), ["f.aes"]);
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    // A file created the ordinary way shows what the umask allows.
    let reference = dir.path().join("reference");
    fs::File::create(&reference).unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;

    let enc = encrypt_file(dir.path(), "a", b"secret");
    assert_eq!(mode(&enc), mode(&reference), "ciphertext follows the umask");

    ok(&cli(&["-d", s(&enc)], PW, b""));
    assert_eq!(mode(&dir.path().join("a")), 0o600, "plaintext is private");
}

// ---------------------------------------------------------------------------
// Official test vectors
// ---------------------------------------------------------------------------

/// The library's vector files. Present in the repository; absent from this
/// crate's published tarball (the library's tarball ships and tests them).
fn vector_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/test_data");
    dir.join("test_vectors_v0.json").is_file().then_some(dir)
}

/// Pulls (plaintext, ciphertext) pairs from the library's pretty-printed
/// vector files without a JSON dependency.
fn vectors(dir: &Path, version: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
    let path = dir.join(format!("test_vectors_v{version}.json"));
    let text = fs::read_to_string(path).unwrap();
    let field = |line: &str, key: &str| -> Option<String> {
        let rest = line.trim().strip_prefix(&format!("\"{key}\": \""))?;
        Some(rest.trim_end_matches(',').trim_end_matches('"').to_string())
    };
    let mut out = Vec::new();
    let mut plain = None;
    for line in text.lines() {
        if let Some(p) = field(line, "plaintext") {
            plain = Some(p.into_bytes());
        } else if let Some(h) = field(line, "ciphertext_hex") {
            let bytes = (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                .collect();
            out.push((plain.take().expect("plaintext before ciphertext"), bytes));
        }
    }
    assert!(!out.is_empty());
    out
}

// ---------------------------------------------------------------------------
// What failures are called
// ---------------------------------------------------------------------------

/// Decrypts `cipher` with `pw` and returns the single failure message.
fn decrypt_failure(cipher: &[u8], pw: &'static str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let enc = dir.path().join("f.aes");
    fs::write(&enc, cipher).unwrap();
    let r = cli(&["-d", "-o", "-", s(&enc)], pw, b"");
    assert!(r.0.is_none());
    assert_eq!(r.1.len(), 1, "expected one failure");
    assert!(r.2.is_empty());
    r.1[0].to_string()
}

/// Each message is produced by a real failure, so a wording change in the
/// library shows up here instead of as a mislabelled error.
#[test]
fn failures_are_described_by_cause() {
    let dir = tempfile::tempdir().unwrap();
    let enc = encrypt_file(dir.path(), "a", &[5u8; 100_000]);
    let good = fs::read(&enc).unwrap();

    let msg = decrypt_failure(&good, "not the password");
    assert!(msg.contains("wrong password"), "{msg}");

    let mut flipped = good.clone();
    *flipped.last_mut().unwrap() ^= 1;
    let msg = decrypt_failure(&flipped, PW);
    assert!(msg.contains("the password was correct"), "{msg}");
    assert!(!msg.contains("wrong password"), "{msg}");

    let msg = decrypt_failure(&good[..good.len() - 10], PW);
    assert!(msg.contains("truncated"), "{msg}");
    assert!(!msg.contains("wrong password"), "{msg}");
}

/// A file that ends inside the header or session block: the library reports a
/// bare read error, which the CLI names. Past the header, the trailer check
/// already says "truncated".
#[test]
fn short_files_are_described() {
    let dir = tempfile::tempdir().unwrap();
    let enc = encrypt_file(dir.path(), "a", &[5u8; 1_000]);
    let good = fs::read(&enc).unwrap();

    let msg = decrypt_failure(b"", PW);
    assert!(msg.ends_with("f.aes: the file is empty"), "{msg}");
    for cut in [2, 4, 20, 80] {
        let msg = decrypt_failure(&good[..cut], PW);
        assert!(
            msg.contains("the file is truncated or damaged"),
            "{cut}: {msg}"
        );
        assert!(!msg.contains("I/O error"), "{cut}: {msg}");
    }
}

/// v0 has no session block: there a payload HMAC failure may be the password.
/// v1 checks the password first, and reports truncation differently.
#[test]
fn legacy_failures_are_described_by_cause() {
    let Some(data) = vector_dir() else {
        eprintln!("skipped: ../tests/test_data not present (published tarball)");
        return;
    };
    let (_, v0) = vectors(&data, 0).pop().unwrap();
    let msg = decrypt_failure(&v0, "not the password");
    assert!(msg.contains("wrong password"), "v0: {msg}");
    let msg = decrypt_failure(&v0[..v0.len() - 10], "Hello");
    assert!(
        msg.contains("truncated") && !msg.contains("wrong password"),
        "v0: {msg}"
    );

    let (_, v1) = vectors(&data, 1).pop().unwrap();
    let msg = decrypt_failure(&v1, "not the password");
    assert!(msg.contains("wrong password"), "v1: {msg}");
    let msg = decrypt_failure(&v1[..v1.len() - 10], "Hello");
    assert!(
        msg.contains("truncated") && !msg.contains("wrong password"),
        "v1: {msg}"
    );
}

#[test]
fn decrypts_official_vectors() {
    let Some(data) = vector_dir() else {
        eprintln!("skipped: ../tests/test_data not present (published tarball)");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    for version in 0..=3 {
        for (i, (plain, cipher)) in vectors(&data, version).into_iter().enumerate() {
            let enc = dir.path().join(format!("v{version}_{i}.aes"));
            fs::write(&enc, &cipher).unwrap();
            let r = cli(&["-d", "-o", "-", s(&enc)], "Hello", b"");
            ok(&r);
            assert_eq!(r.2, plain, "v{version} vector {i}");
        }
    }
}
