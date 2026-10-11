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
    let o = aescrypt(&["--help"]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("--password-command"));

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
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("wrong password"), "{}", stderr(&o));
    assert!(!dir.path().join("b").exists());
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

    fn spawn(args: &[&str]) -> Session {
        let mut cmd = Command::new(BIN);
        cmd.args(args);
        let mut s = Session::spawn(cmd).expect("spawn in pty");
        s.set_expect_timeout(Some(Duration::from_secs(30)));
        s
    }

    /// `Exited(pid, code)` vs `Signaled(..)`, via Debug to avoid depending on
    /// expectrl's nix version.
    fn exit_status(s: &Session) -> String {
        format!("{:?}", s.get_process().wait().unwrap())
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
        let status = exit_status(&p);
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
        assert!(exit_status(&p).ends_with(", 1)"));
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
        assert!(exit_status(&p).ends_with(", 0)"));
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
        assert!(exit_status(&p).ends_with(", 0)"));
        assert!(decrypts_with(&dir.path().join("a.aes"), &pass));
    }

    /// Ctrl-C at the prompt must end in a normal exit (130), not death by
    /// SIGINT: only then has rpassword's guard turned terminal echo back on.
    #[test]
    fn prompt_ctrl_c_restores_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("a");
        fs::write(&plain, b"typed").unwrap();
        let mut p = spawn(&["-e", s(&plain)]);
        p.expect("Password: ").unwrap();
        p.send("\x03").unwrap();
        let status = exit_status(&p);
        assert!(
            status.contains("Exited") && status.ends_with(", 130)"),
            "{status}"
        );
        assert!(!dir.path().join("a.aes").exists());
    }
}
