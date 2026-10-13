// ============================================================================
// FILE: aescrypt-cli/src/password.rs
// Where passwords come from. There is deliberately no flag or environment
// variable that carries one: argv is world-readable through `ps` and lands in
// shell history, and environments leak into children and crash reports.
// ============================================================================

use std::{
    io::{self, IsTerminal, Write},
    process::{Command, Stdio},
};

use aescrypt_rs::aliases::PasswordString;
use secure_gate::{Fixed, RevealSecret};
use zeroize::Zeroize;

use crate::{CliError, Mode, signals};

/// Below this many characters an encryption password draws a warning. Not a
/// refusal: the format and the official tool accept short passwords.
pub const SHORT_PASSWORD: usize = 12;

/// Supplies the one password a run uses.
#[doc(hidden)]
pub trait PasswordSource {
    fn password(&self, mode: Mode) -> Result<PasswordString, CliError>;
}

// ---------------------------------------------------------------------------
// Terminal prompt
// ---------------------------------------------------------------------------

/// Prompts on the controlling terminal (`/dev/tty`, or the console on
/// Windows), so data can still be piped through stdin.
pub struct TtyPrompt;

impl PasswordSource for TtyPrompt {
    fn password(&self, mode: Mode) -> Result<PasswordString, CliError> {
        let first = prompt("Password: ")?;
        if mode == Mode::Decrypt {
            // Empty is passed through: `decrypt` accepts it for compatibility
            // with third-party tools that allow empty passwords.
            return Ok(first);
        }

        if first.with_secret(|s| s.is_empty()) {
            // Like age: an empty answer asks for a generated passphrase. Only
            // when stderr is a terminal, so it cannot end up in a log file.
            if !io::stderr().is_terminal() {
                return Err(CliError::Password(
                    "empty password (a passphrase is generated only when stderr is a terminal)"
                        .into(),
                ));
            }
            let generated = generate_passphrase();
            // If the passphrase cannot be shown, nothing may be encrypted with
            // it: the file would be unrecoverable.
            generated
                .with_secret(|s| {
                    let mut err = io::stderr().lock();
                    writeln!(err, "Generated passphrase: {s}")?;
                    writeln!(
                        err,
                        "Save it now. It is not stored anywhere and cannot be recovered."
                    )?;
                    err.flush()
                })
                .map_err(|e| {
                    CliError::Password(format!("could not display the generated passphrase: {e}"))
                })?;
            return Ok(generated);
        }

        let confirm = prompt("Confirm password: ")?;
        let same = first.with_secret(|a| confirm.with_secret(|b| a == b));
        if !same {
            return Err(CliError::Password("passwords do not match".into()));
        }
        warn_if_short(&first);
        Ok(first)
    }
}

fn prompt(label: &str) -> Result<PasswordString, CliError> {
    signals::prompting(|had_terminal| match rpassword::prompt_password(label) {
        // On macOS a hang-up reads as an empty line rather than an error. Left
        // alone, encrypt would generate a passphrase nobody will see.
        Ok(s) if s.is_empty() && had_terminal && signals::terminal_hung_up() => {
            Err(CliError::TerminalLost)
        }
        // Moved straight into the wrapper: `String` -> `Box<String>` reuses the
        // heap buffer, so no unzeroized copy is left behind by this step.
        Ok(s) => Ok(PasswordString::new(s)),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Err(CliError::Interrupted),
        // The terminal was there when the prompt started, so a failed read
        // means it went away (hang-up, EIO). The SIGHUP handler may not have
        // run yet; exit the way it would rather than claim there was never a
        // terminal.
        Err(_) if had_terminal => Err(CliError::TerminalLost),
        Err(e) => Err(CliError::NoTty(e)),
    })
}

fn warn_if_short(pw: &PasswordString) {
    if pw.with_secret(|s| s.chars().count()) < SHORT_PASSWORD {
        crate::say(&format!(
            "warning: password is shorter than {SHORT_PASSWORD} characters; \
             consider leaving the prompt empty to generate one"
        ));
    }
}

// ---------------------------------------------------------------------------
// --password-command
// ---------------------------------------------------------------------------

/// Runs a command and uses its stdout (minus one trailing newline) as the
/// password, e.g. `pass show backup`. Never asks for confirmation.
pub struct CommandSource {
    pub command: String,
}

impl PasswordSource for CommandSource {
    fn password(&self, _mode: Mode) -> Result<PasswordString, CliError> {
        let mut cmd = shell(&self.command);
        // stdin null: the command must not swallow data piped to us. stderr is
        // inherited so its own errors and pinentry-style prompts reach the user.
        let output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|e| CliError::Password(format!("--password-command: {e}")))?;

        let mut bytes = output.stdout;
        if !output.status.success() {
            bytes.zeroize();
            return Err(CliError::Password(format!(
                "--password-command exited with {}",
                output.status
            )));
        }
        if bytes.ends_with(b"\n") {
            bytes.pop();
            if bytes.ends_with(b"\r") {
                bytes.pop();
            }
        }
        if bytes.is_empty() {
            bytes.zeroize();
            return Err(CliError::Password(
                "--password-command printed an empty password".into(),
            ));
        }
        match String::from_utf8(bytes) {
            Ok(s) => Ok(PasswordString::new(s)),
            Err(e) => {
                e.into_bytes().zeroize();
                Err(CliError::Password(
                    "--password-command printed invalid UTF-8".into(),
                ))
            }
        }
    }
}

#[cfg(unix)]
fn shell(command: &str) -> Command {
    let mut c = Command::new("sh");
    c.arg("-c").arg(command);
    c
}

#[cfg(windows)]
fn shell(command: &str) -> Command {
    use std::os::windows::process::CommandExt;
    // `arg` would apply MSVC quoting rules, which cmd does not understand: a
    // command containing a double quote reaches it with `\"` and is mangled.
    // `/S` makes cmd strip exactly the outer quotes and leave the rest as is.
    let mut c = Command::new("cmd");
    c.raw_arg(format!("/S /C \"{command}\""));
    c
}

// ---------------------------------------------------------------------------
// Generated passphrases
// ---------------------------------------------------------------------------

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Bytes of entropy in a generated passphrase: 160 bits, encoded as exactly 32
/// base32 characters.
const GENERATED_BYTES: usize = 20;

/// Length of a generated passphrase: 8 groups of 4 characters, 7 dashes.
pub const GENERATED_LEN: usize = 39;

/// A random passphrase such as `k7qd-m2xa-…`: lowercase RFC 4648 base32 (no
/// 0/1/8/9, so nothing to confuse with o/l), grouped in fours.
#[doc(hidden)]
pub fn generate_passphrase() -> PasswordString {
    let raw: Fixed<[u8; GENERATED_BYTES]> = Fixed::from_random();
    raw.with_secret(|bytes| {
        // Pre-sized so the string never reallocates and leaves a stray copy.
        let mut out = String::with_capacity(GENERATED_LEN);
        let mut acc: u64 = 0;
        let mut bits = 0u32;
        let mut written = 0usize;
        for &b in bytes {
            acc = (acc << 8) | u64::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                if written > 0 && written % 4 == 0 {
                    out.push('-');
                }
                out.push(BASE32[((acc >> bits) & 31) as usize] as char);
                written += 1;
            }
        }
        acc.zeroize();
        debug_assert_eq!(out.len(), GENERATED_LEN);
        PasswordString::new(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_shape() {
        let p = generate_passphrase();
        p.with_secret(|s| {
            assert_eq!(s.len(), GENERATED_LEN);
            let groups: Vec<&str> = s.split('-').collect();
            assert_eq!(groups.len(), 8);
            for g in groups {
                assert_eq!(g.len(), 4);
                assert!(g.bytes().all(|c| BASE32.contains(&c)));
            }
        });
    }

    #[test]
    fn generated_differs() {
        let a = generate_passphrase();
        let b = generate_passphrase();
        assert!(!a.with_secret(|x| b.with_secret(|y| x == y)));
    }
}
