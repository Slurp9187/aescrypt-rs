//! tests/binary.rs
//! Runs the real `aescrypt-cli` binary: argument handling, --password-command,
//! signals, and (Unix) the terminal prompt through a pseudo-terminal.

use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
};

const BIN: &str = env!("CARGO_BIN_EXE_aescrypt-cli");

/// A --password-command that prints `pw`.
fn print_cmd(pw: &str) -> String {
    if cfg!(windows) {
        format!("echo {pw}")
    } else {
        format!("printf '%s' '{pw}'")
    }
}

fn aescrypt(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn aescrypt-cli")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn help_and_version() {
    for flag in ["-h", "--help"] {
        let o = aescrypt(&[flag]);
        assert!(o.status.success());
        let h = String::from_utf8_lossy(&o.stdout);
        for want in [
            "--password-command",
            "--password-file",
            "Examples:",
            "-- *",
            "generate a passphrase",
            "Exit codes:",
            "3 wrong password",
        ] {
            assert!(h.contains(want), "{flag} lacks {want:?}:\n{h}");
        }
    }

    let o = aescrypt(&["--version"]);
    assert!(o.status.success());
    let v = String::from_utf8_lossy(&o.stdout);
    assert!(v.contains("(aescrypt-rs "), "{v}");
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &["a"][..],               // no -e/-d
        &["-e", "-d", "a"],       // both
        &["-e", "-p", "pw", "a"], // there is no -p
        &["-e", "--password", "pw", "a"],
        &["-e", "-o", "x", "a", "b"],
    ] {
        let o = aescrypt(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", stderr(&o));
    }
}

#[test]
fn roundtrip_with_password_command() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a.txt");
    fs::write(&plain, b"through the binary").unwrap();
    let cmd = print_cmd("binary-test-pw");

    let o = aescrypt(&[
        "-e",
        "--iterations",
        "5",
        "--password-command",
        &cmd,
        s(&plain),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    fs::remove_file(&plain).unwrap();

    let enc = dir.path().join("a.txt.aes");
    let o = aescrypt(&["-d", "--password-command", &cmd, s(&enc)]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(fs::read(&plain).unwrap(), b"through the binary");

    let o = aescrypt(&[
        "-d",
        "-o",
        s(&dir.path().join("b")),
        "--password-command",
        &print_cmd("wrong"),
        s(&enc),
    ]);
    assert_eq!(o.status.code(), Some(3));
    assert!(stderr(&o).contains("wrong password"), "{}", stderr(&o));
    assert!(!dir.path().join("b").exists());
}

/// 3 only when every failure was a wrong password; anything else in the mix,
/// or damage the password check passed, is 1.
#[test]
fn exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let pw = print_cmd("right");
    let mut encs = Vec::new();
    for name in ["a", "b"] {
        let plain = dir.path().join(name);
        fs::write(&plain, b"data").unwrap();
        let o = aescrypt(&[
            "-e",
            "--iterations",
            "5",
            "--password-command",
            &pw,
            s(&plain),
        ]);
        assert!(o.status.success(), "{}", stderr(&o));
        encs.push(dir.path().join(format!("{name}.aes")));
    }
    let dec = |args: &[&str]| {
        let mut v = vec!["-d", "--force", "--password-command"];
        v.extend_from_slice(args);
        aescrypt(&v)
    };
    let wrong = print_cmd("wrong");

    let o = dec(&[&wrong, s(&encs[0]), s(&encs[1])]);
    assert_eq!(o.status.code(), Some(3), "both wrong: {}", stderr(&o));

    let missing = dir.path().join("missing.aes");
    let o = dec(&[&wrong, s(&encs[0]), s(&missing)]);
    assert_eq!(o.status.code(), Some(1), "wrong + missing: {}", stderr(&o));

    // Last byte of the payload HMAC: the password check passes, the data
    // check fails. Damage, not a wrong password.
    let mut bytes = fs::read(&encs[1]).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&encs[1], bytes).unwrap();
    let o = dec(&[&pw, s(&encs[1])]);
    assert_eq!(o.status.code(), Some(1), "tampered: {}", stderr(&o));
    assert!(
        stderr(&o).contains("password was correct"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn failing_password_command() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a");
    fs::write(&plain, b"x").unwrap();
    let o = aescrypt(&["-e", "--password-command", "exit 3", s(&plain)]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        stderr(&o).contains("--password-command exited"),
        "{}",
        stderr(&o)
    );
    assert!(!dir.path().join("a.aes").exists());
}

/// One trailing `\n` or `\r\n` is not part of the password.
#[cfg(unix)]
#[test]
fn password_command_strips_one_newline() {
    for printed in [r"pw-strip\n", r"pw-strip\r\n"] {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("a");
        fs::write(&plain, b"x").unwrap();
        let cmd = format!("printf '{printed}'");
        let o = aescrypt(&[
            "-e",
            "--iterations",
            "5",
            "--password-command",
            &cmd,
            s(&plain),
        ]);
        assert!(o.status.success(), "{}", stderr(&o));
        let o = aescrypt(&[
            "-d",
            "-o",
            "-",
            "--password-command",
            &print_cmd("pw-strip"),
            s(&dir.path().join("a.aes")),
        ]);
        assert!(o.status.success(), "{printed}: {}", stderr(&o));
        assert_eq!(o.stdout, b"x");
    }
}

/// The command reaches `cmd` as written. A quoted program path (the usual
/// shape for a password manager under `Program Files`) runs, and a double
/// quote inside the command is part of the password, not an escaped `\"`.
#[cfg(windows)]
#[test]
fn password_command_keeps_quotes() {
    let dir = tempfile::tempdir().unwrap();
    let bat_dir = dir.path().join("my dir");
    fs::create_dir(&bat_dir).unwrap();
    let bat = bat_dir.join("pw.bat");
    fs::write(&bat, "@echo quoted-pw\r\n").unwrap();
    let plain = dir.path().join("a.txt");
    fs::write(&plain, b"x").unwrap();
    let enc = dir.path().join("a.txt.aes");

    let quoted_path = format!("\"{}\"", s(&bat));
    let o = aescrypt(&[
        "-e",
        "--iterations",
        "5",
        "--password-command",
        &quoted_path,
        s(&plain),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let o = aescrypt(&[
        "-d",
        "-o",
        "-",
        "--password-command",
        "echo quoted-pw",
        s(&enc),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(o.stdout, b"x");

    fs::remove_file(&enc).unwrap();
    fs::write(&bat, "@echo \"a b\"\r\n").unwrap();
    let o = aescrypt(&[
        "-e",
        "--iterations",
        "5",
        "--password-command",
        "echo \"a b\"",
        s(&plain),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let o = aescrypt(&["-d", "-o", "-", "--password-command", &quoted_path, s(&enc)]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(o.stdout, b"x");
}

/// With --force, a rename the OS refuses (a device name) reports the OS error,
/// not advice to pass the --force that was already given.
#[cfg(windows)]
#[test]
fn force_rename_failure_is_not_use_force() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a");
    fs::write(&plain, b"x").unwrap();
    let o = aescrypt(&[
        "-e",
        "--force",
        "--iterations",
        "5",
        "--password-command",
        "echo pw",
        "-o",
        "CON",
        s(&plain),
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(!stderr(&o).contains("use --force"), "{}", stderr(&o));
    assert!(o.stdout.is_empty());
}

/// An unwritable stderr must not turn an ordinary failure into a panic (101).
#[cfg(target_os = "linux")]
#[test]
fn unwritable_stderr_does_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let o = Command::new(BIN)
        .args([
            "-e",
            "--password-command",
            "printf pw",
            s(&dir.path().join("missing")),
        ])
        .stdin(Stdio::null())
        .stderr(full)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{:?}", o.status);
}

#[cfg(unix)]
#[test]
fn empty_password_command_output() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a");
    fs::write(&plain, b"x").unwrap();
    let o = aescrypt(&["-e", "--password-command", "printf ''", s(&plain)]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("empty password"), "{}", stderr(&o));
}

// ---------------------------------------------------------------------------
// --password-file
// ---------------------------------------------------------------------------

/// The file's contents are the password; one trailing `\r\n` (as Windows
/// tools write) or `\n` is not part of it.
#[test]
fn roundtrip_with_password_file() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a.txt");
    fs::write(&plain, b"from a file").unwrap();
    let pw = dir.path().join("pw.txt");
    fs::write(&pw, b"file pw\r\n").unwrap();

    let o = aescrypt(&[
        "-e",
        "--iterations",
        "5",
        "--password-file",
        s(&pw),
        s(&plain),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let enc = dir.path().join("a.txt.aes");
    let o = aescrypt(&[
        "-d",
        "-o",
        "-",
        "--password-command",
        &print_cmd("file pw"),
        s(&enc),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(o.stdout, b"from a file");

    fs::write(&pw, b"file pw\n").unwrap();
    let o = aescrypt(&["-d", "-o", "-", "--password-file", s(&pw), s(&enc)]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(o.stdout, b"from a file");
}

/// A UTF-8 byte order mark, as Windows PowerShell 5.1 writes, is not part of
/// the password: the file must decrypt with the same password typed or
/// printed without one.
#[test]
fn password_file_ignores_bom() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a");
    fs::write(&plain, b"bom").unwrap();
    let pw = dir.path().join("pw.txt");
    fs::write(&pw, b"\xEF\xBB\xBFpw\r\n").unwrap();
    let o = aescrypt(&[
        "-e",
        "--iterations",
        "5",
        "--password-file",
        s(&pw),
        s(&plain),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let enc = dir.path().join("a.aes");
    let o = aescrypt(&[
        "-d",
        "-o",
        "-",
        "--password-command",
        &print_cmd("pw"),
        s(&enc),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(o.stdout, b"bom");
}

#[test]
fn password_file_errors() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a");
    fs::write(&plain, b"x").unwrap();
    let pw = dir.path().join("pw");
    let enc = |pw: &Path| aescrypt(&["-e", "--password-file", s(pw), s(&plain)]);

    fs::write(&pw, b"\n").unwrap();
    let o = enc(&pw);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("empty password"), "{}", stderr(&o));

    let o = enc(&dir.path().join("missing"));
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("--password-file"), "{}", stderr(&o));

    fs::write(&pw, vec![b'a'; 64 * 1024 + 1]).unwrap();
    let o = enc(&pw);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("larger than 64 KiB"), "{}", stderr(&o));

    fs::write(&pw, b"pw").unwrap();
    let o = aescrypt(&[
        "-e",
        "--password-file",
        s(&pw),
        "--password-command",
        &print_cmd("pw"),
        s(&plain),
    ]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(!dir.path().join("a.aes").exists());
}

/// The password file is read before anything is written, so no output may
/// replace it, --force or not.
#[test]
fn password_file_is_never_an_output() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a");
    fs::write(&plain, b"x").unwrap();
    let pw = dir.path().join("pw");
    fs::write(&pw, b"keep me").unwrap();
    let o = aescrypt(&[
        "-e",
        "--force",
        "--password-file",
        s(&pw),
        "-o",
        s(&pw),
        s(&plain),
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("is the --password-file"),
        "{}",
        stderr(&o)
    );
    assert_eq!(fs::read(&pw).unwrap(), b"keep me");
}

#[cfg(unix)]
#[test]
fn password_file_mode_warning() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a");
    fs::write(&plain, b"x").unwrap();
    let pw = dir.path().join("pw");
    fs::write(&pw, b"pw").unwrap();
    for (mode, warns) in [(0o644, true), (0o600, false)] {
        fs::set_permissions(&pw, fs::Permissions::from_mode(mode)).unwrap();
        let _ = fs::remove_file(dir.path().join("a.aes"));
        let o = aescrypt(&[
            "-e",
            "--iterations",
            "5",
            "--password-file",
            s(&pw),
            s(&plain),
        ]);
        assert!(o.status.success(), "{}", stderr(&o));
        assert_eq!(
            stderr(&o).contains("accessible by other users"),
            warns,
            "{mode:o}"
        );
    }
}

/// Plaintext reaches stdout only after verification, and the staging file in
/// the temp dir is gone afterwards.
#[test]
fn tampered_to_stdout_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a");
    fs::write(&plain, vec![9u8; 100_000]).unwrap();
    let cmd = print_cmd("tamper-test");
    let o = aescrypt(&[
        "-e",
        "--iterations",
        "5",
        "--password-command",
        &cmd,
        s(&plain),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));

    let enc = dir.path().join("a.aes");
    let mut bytes = fs::read(&enc).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&enc, &bytes).unwrap();

    let o = Command::new(BIN)
        .args(["-d", "-o", "-", "--password-command", &cmd, s(&enc)])
        .env("TMPDIR", tmp.path())
        .env("TMP", tmp.path())
        .env("TEMP", tmp.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(
        o.stdout.is_empty(),
        "{} unverified bytes on stdout",
        o.stdout.len()
    );
    assert_eq!(
        fs::read_dir(tmp.path()).unwrap().count(),
        0,
        "staging file left behind"
    );
}

/// Windows counterpart of `unix::no_terminal`: started with no console at all
/// (`DETACHED_PROCESS`), the prompt must fail with a pointer to
/// --password-command instead of waiting for input that cannot come.
#[cfg(windows)]
#[test]
fn no_console() {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a");
    fs::write(&plain, b"x").unwrap();
    let mut child = Command::new(BIN)
        .args(["-e", s(&plain)])
        .creation_flags(DETACHED_PROCESS)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Bounded: a prompt that waits forever must fail the test, not hang it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("still waiting at the prompt with no console");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    assert_eq!(status.code(), Some(1), "{err}");
    assert!(err.contains("--password-command"), "{err}");
    assert!(!dir.path().join("a.aes").exists());
}

/// Ctrl-C at the prompt on Windows exits 130 at once. Before, the console read
/// kept waiting until Enter was pressed, so Ctrl-C looked ignored. The CLI
/// runs in a real console with no window (`CREATE_NO_WINDOW`); a helper (this
/// test binary again, running `windows_ctrl_c_sender`) attaches to that
/// console and sends CTRL_C_EVENT, which is what the key does.
#[cfg(windows)]
#[test]
fn ctrl_c_at_prompt_exits_at_once() {
    use std::os::windows::process::CommandExt;
    use std::time::{Duration, Instant};
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("a");
    fs::write(&plain, b"x").unwrap();
    let mut child = Command::new(BIN)
        .args(["-e", s(&plain)])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .unwrap();
    // Time to reach the prompt; it must still be waiting there.
    std::thread::sleep(Duration::from_millis(1500));
    assert!(child.try_wait().unwrap().is_none(), "exited before Ctrl-C");

    let sent = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "windows_ctrl_c_sender",
            "--ignored",
            "--nocapture",
        ])
        .env("AESCRYPT_CLI_CTRL_C_TARGET", child.id().to_string())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .unwrap();
    assert!(
        sent.status.success(),
        "sender failed: {}",
        String::from_utf8_lossy(&sent.stdout)
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("still at the prompt 5s after Ctrl-C");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(130));
    assert!(!dir.path().join("a.aes").exists());
}

/// Not a test on its own: `ctrl_c_at_prompt_exits_at_once` runs it in a
/// separate process, because attaching to another console means leaving this
/// one, which would take the test runner's console with it.
#[cfg(windows)]
#[test]
#[ignore = "helper process for ctrl_c_at_prompt_exits_at_once"]
fn windows_ctrl_c_sender() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn FreeConsole() -> i32;
        fn AttachConsole(pid: u32) -> i32;
        fn SetConsoleCtrlHandler(handler: *const std::ffi::c_void, add: i32) -> i32;
        fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
    }
    let pid: u32 = std::env::var("AESCRYPT_CLI_CTRL_C_TARGET")
        .expect("run by ctrl_c_at_prompt_exits_at_once")
        .parse()
        .unwrap();
    // SAFETY: plain kernel32 calls with integer arguments and a null handler.
    unsafe {
        FreeConsole();
        assert!(AttachConsole(pid) != 0, "AttachConsole failed");
        // This process ignores the event; the CLI, on the same console, gets it.
        SetConsoleCtrlHandler(std::ptr::null(), 1);
        assert!(
            GenerateConsoleCtrlEvent(0, 0) != 0,
            "GenerateConsoleCtrlEvent failed"
        );
    }
}

// ---------------------------------------------------------------------------
// Unix: no terminal, signals, and the real prompt
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod unix {
    use super::*;
    use std::{
        io::Write,
        os::unix::process::{CommandExt, ExitStatusExt},
        thread,
        time::{Duration, Instant},
    };

    /// Without a controlling terminal and without --password-command the CLI
    /// must fail with a pointer to the alternative, not hang.
    #[test]
    fn no_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("a");
        fs::write(&plain, b"x").unwrap();
        let mut cmd = Command::new(BIN);
        cmd.args(["-e", s(&plain)]).stdin(Stdio::null());
        // SAFETY: setsid is async-signal-safe; it detaches the child from any
        // controlling terminal the test runner has.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let o = cmd.output().unwrap();
        assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
        assert!(stderr(&o).contains("--password-command"), "{}", stderr(&o));
        assert!(!dir.path().join("a.aes").exists());
    }

    /// SIGINT while decrypting deletes the in-flight temp file and exits 130.
    #[test]
    fn interrupt_removes_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("big");
        fs::write(&plain, vec![1u8; 200_000]).unwrap();
        let cmd = print_cmd("signal-test");
        let o = aescrypt(&[
            "-e",
            "--iterations",
            "5",
            "--password-command",
            &cmd,
            s(&plain),
        ]);
        assert!(o.status.success(), "{}", stderr(&o));
        let cipher = fs::read(dir.path().join("big.aes")).unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir.path().join("out");
        let mut child = Command::new(BIN)
            .args(["-d", "--password-command", &cmd, "-o", s(&out), "-"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Feed part of the file and keep the pipe open, so decryption is
        // mid-stream with its temp file on disk.
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&cipher[..cipher.len() / 2]).unwrap();
        stdin.flush().unwrap();

        let deadline = Instant::now() + Duration::from_secs(20);
        while fs::read_dir(out_dir.path()).unwrap().count() == 0 {
            assert!(Instant::now() < deadline, "temp file never appeared");
            thread::sleep(Duration::from_millis(20));
        }
        // SAFETY: plain FFI call with a pid we own.
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGINT);
        }
        let status = child.wait().unwrap();
        drop(stdin);
        assert_eq!(status.signal(), None, "killed by a signal: {status:?}");
        assert_eq!(status.code(), Some(130), "{status:?}");
        assert_eq!(
            fs::read_dir(out_dir.path()).unwrap().count(),
            0,
            "temp file left behind"
        );
    }

    // -----------------------------------------------------------------------
    // The prompt, through a pseudo-terminal
    // -----------------------------------------------------------------------

    use expectrl::{Regex, Session};

    /// Runs the binary on a pty. expectrl creates the pty with echo off, which
    /// would make "echo restored" impossible to tell from "never touched", so
    /// echo is switched on first and the shell then `exec`s the binary (same
    /// pid, so signals reach it directly).
    fn spawn(args: &[&str]) -> Session {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "stty echo && exec \"$@\"", "sh", BIN])
            .args(args);
        let mut s = Session::spawn(cmd).expect("spawn in pty");
        s.set_expect_timeout(Some(Duration::from_secs(30)));
        s
    }

    /// Waits for exit and returns `Exited(pid, code)` vs `Signaled(..)`, via
    /// Debug to avoid depending on expectrl's nix version.
    ///
    /// Reads the pty the whole time. On macOS a process cannot finish exiting
    /// while its terminal holds output nobody has read, so a plain blocking
    /// `wait()` never returns there. Bounded: a process that does not exit
    /// must fail the test, not hang it.
    fn exit_status(p: &mut Session) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            // WouldBlock, EOF and Linux's EIO after the slave closes all just
            // mean "nothing more to read now".
            while let Ok(n @ 1..) = p.try_read(&mut buf) {
                out.extend_from_slice(&buf[..n]);
            }
            // Non-blocking waitpid; the first non-StillAlive result reaps the
            // child, so it is the one to keep.
            let st = format!("{:?}", p.get_process().status().unwrap());
            if st != "StillAlive" {
                return st;
            }
            if Instant::now() > deadline {
                signal(p, libc::SIGKILL);
                panic!(
                    "still running after 10s; output: {:?}",
                    String::from_utf8_lossy(&out)
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn decrypts_with(enc: &Path, pw: &str) -> bool {
        let o = aescrypt(&[
            "-d",
            "-o",
            "-",
            "--password-command",
            &print_cmd(pw),
            s(enc),
        ]);
        o.status.success()
    }

    #[test]
    fn prompt_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("a");
        fs::write(&plain, b"typed").unwrap();
        let mut p = spawn(&["-e", "--iterations", "5", s(&plain)]);
        p.expect("Password: ").unwrap();
        p.send_line("a long enough password").unwrap();
        p.expect("Confirm password: ").unwrap();
        p.send_line("a long enough password").unwrap();
        let status = exit_status(&mut p);
        assert!(
            status.contains("Exited") && status.ends_with(", 0)"),
            "{status}"
        );
        assert!(decrypts_with(
            &dir.path().join("a.aes"),
            "a long enough password"
        ));
    }

    #[test]
    fn prompt_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("a");
        fs::write(&plain, b"typed").unwrap();
        let mut p = spawn(&["-e", "--iterations", "5", s(&plain)]);
        p.expect("Password: ").unwrap();
        p.send_line("first password here").unwrap();
        p.expect("Confirm password: ").unwrap();
        p.send_line("second password here").unwrap();
        p.expect("do not match").unwrap();
        assert!(exit_status(&mut p).ends_with(", 1)"));
        assert!(!dir.path().join("a.aes").exists());
    }

    #[test]
    fn prompt_short_password_warns() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("a");
        fs::write(&plain, b"typed").unwrap();
        let mut p = spawn(&["-e", "--iterations", "5", s(&plain)]);
        p.expect("Password: ").unwrap();
        p.send_line("short").unwrap();
        p.expect("Confirm password: ").unwrap();
        p.send_line("short").unwrap();
        p.expect("shorter than").unwrap();
        assert!(exit_status(&mut p).ends_with(", 0)"));
        assert!(decrypts_with(&dir.path().join("a.aes"), "short"));
    }

    #[test]
    fn prompt_empty_generates_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("a");
        fs::write(&plain, b"typed").unwrap();
        let mut p = spawn(&["-e", "--iterations", "5", s(&plain)]);
        p.expect("Password: ").unwrap();
        p.send_line("").unwrap();
        let caps = p
            .expect(Regex(
                "Generated passphrase: ([a-z2-7]{4}(-[a-z2-7]{4}){7})",
            ))
            .unwrap();
        let pass = String::from_utf8(caps.get(1).unwrap().to_vec()).unwrap();
        assert!(exit_status(&mut p).ends_with(", 0)"));
        assert!(decrypts_with(&dir.path().join("a.aes"), &pass));
    }

    fn echo_on(p: &Session) -> bool {
        p.get_process().get_echo().expect("read pty echo flag")
    }

    /// Starts an encrypt prompt and returns once rpassword has turned echo off.
    fn at_prompt(dir: &Path) -> Session {
        let plain = dir.join("a");
        fs::write(&plain, b"typed").unwrap();
        let mut p = spawn(&["-e", s(&plain)]);
        p.expect("Password: ").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while echo_on(&p) {
            assert!(Instant::now() < deadline, "prompt never turned echo off");
            thread::sleep(Duration::from_millis(10));
        }
        p
    }

    /// After a signal at the prompt: a normal exit 130 (not death by signal,
    /// not a panic's 101), echo back on, and nothing encrypted.
    fn assert_clean_interrupt(p: &mut Session, dir: &Path) {
        let status = exit_status(p);
        assert!(
            status.contains("Exited") && status.ends_with(", 130)"),
            "{status}"
        );
        assert!(echo_on(p), "terminal left with echo off");
        assert!(!dir.join("a.aes").exists());
    }

    fn signal(p: &Session, sig: libc::c_int) {
        let pid = p.get_process().pid().as_raw();
        // SAFETY: plain FFI call with a pid we own.
        unsafe {
            libc::kill(pid, sig);
        }
    }

    /// Ctrl-C typed at the prompt.
    #[test]
    fn prompt_ctrl_c_restores_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = at_prompt(dir.path());
        p.send("\x03").unwrap();
        assert_clean_interrupt(&mut p, dir.path());
    }

    /// SIGTERM and SIGINT from outside must not wait for the user to finish
    /// typing.
    #[test]
    fn prompt_external_signals_exit_at_once() {
        for sig in [libc::SIGTERM, libc::SIGINT] {
            let dir = tempfile::tempdir().unwrap();
            let mut p = at_prompt(dir.path());
            signal(&p, sig);
            assert_clean_interrupt(&mut p, dir.path());
        }
    }

    /// Opens a pty pair: (master, slave).
    fn openpty() -> (fs::File, fs::File) {
        use std::os::fd::FromRawFd;
        let (mut m, mut sl) = (0, 0);
        // SAFETY: out-pointers to two c_ints; null name/termios/winsize.
        let rc = unsafe {
            libc::openpty(
                &mut m,
                &mut sl,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
        // openpty's fds are inheritable. A child holding the master would
        // keep the terminal open after the test closes its copy.
        // SAFETY: fcntl on fds owned here.
        unsafe {
            libc::fcntl(m, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(sl, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        // SAFETY: both fds were just returned by openpty and are owned here.
        unsafe { (fs::File::from_raw_fd(m), fs::File::from_raw_fd(sl)) }
    }

    /// Closing the terminal while the prompt waits ends in exit 130, the same
    /// as the SIGHUP handler, never "no terminal available" — whichever of the
    /// failed read and the signal gets there first. Repeated, because that is
    /// a race; stderr goes to a file, which is where it was lost half the time.
    #[test]
    fn prompt_terminal_closed() {
        use std::io::Read;

        for round in 0..30 {
            let dir = tempfile::tempdir().unwrap();
            let plain = dir.path().join("a");
            fs::write(&plain, b"x").unwrap();
            let errlog = dir.path().join("stderr");
            let (mut master, slave) = openpty();

            let mut cmd = Command::new(BIN);
            cmd.args(["-e", s(&plain)])
                .stdin(Stdio::from(slave.try_clone().unwrap()))
                .stdout(Stdio::from(slave.try_clone().unwrap()))
                .stderr(fs::File::create(&errlog).unwrap());
            // SAFETY: setsid and ioctl are async-signal-safe. The child gets a
            // new session with the pty slave (its stdin) as controlling
            // terminal, so /dev/tty is the pty.
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    if libc::ioctl(0, libc::TIOCSCTTY as _, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = cmd.spawn().unwrap();
            drop(slave);

            let mut seen = Vec::new();
            let mut buf = [0u8; 256];
            while !seen.windows(10).any(|w| w == b"Password: ") {
                let n = master.read(&mut buf).expect("prompt never appeared");
                assert!(n > 0, "pty closed before the prompt");
                seen.extend_from_slice(&buf[..n]);
            }
            drop(master);

            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(st) = child.try_wait().unwrap() {
                    break st;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    panic!("round {round}: still running after the terminal closed");
                }
                thread::sleep(Duration::from_millis(10));
            };
            let err = fs::read_to_string(&errlog).unwrap();
            assert_eq!(status.code(), Some(130), "round {round}: {status:?} {err}");
            assert!(!err.contains("no terminal"), "round {round}: {err}");
            assert!(!dir.path().join("a.aes").exists());
        }
    }

    /// SIGHUP (terminal closed) must not end in a panic while printing.
    #[test]
    fn prompt_hangup() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = at_prompt(dir.path());
        signal(&p, libc::SIGHUP);
        assert_clean_interrupt(&mut p, dir.path());
    }
}
