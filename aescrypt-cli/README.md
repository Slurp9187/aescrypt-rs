# aescrypt-cli

aescrypt-cli is an independent tool. It is not affiliated with or endorsed by
Paul E. Jones or the official AES Crypt project, and it is not the official
`aescrypt` command-line program.

A command-line tool for [AES Crypt](https://www.aescrypt.com/) files, built on
[`aescrypt-rs`](https://crates.io/crates/aescrypt-rs). It decrypts every
format version (v0–v3) and writes v3.

```sh
cargo install aescrypt-cli --version 0.2.0-rc.11
```

Requires Rust 1.85 or newer. Until 0.2.0 is released only release candidates
exist, and `cargo install` wants the version named for those.

## Usage

```text
aescrypt-cli -e|-d [-o OUTPUT] [--force] [--iterations N]
                   [--password-command CMD | --password-file PATH] FILE...
```

| Command | Result |
| --- | --- |
| `aescrypt-cli -e report.pdf` | writes `report.pdf.aes` |
| `aescrypt-cli -d report.pdf.aes` | writes `report.pdf` |
| `aescrypt-cli -e a.txt b.txt` | encrypts both, with one password |
| `aescrypt-cli -d -o out.bin data` | names the output explicitly |
| `tar c dir \| aescrypt-cli -e -o dir.tar.aes -` | reads stdin (`-`); needs `-o` |
| `aescrypt-cli -d -o - backup.tar.aes \| tar x` | writes stdout (`-o -`) |

When passing files with a wildcard, put `--` before them
(`aescrypt-cli -e -- *`), as with `rm` or `tar`. Otherwise a file whose name
starts with `-`, such as one named `--force` or `--password-command`, is read
as that option. Anyone who can create files in the folder could then turn on
`--force`, or make aescrypt-cli run a command of their choosing.

The flags follow the official `aescrypt` tool, except that there is no `-p`
or `-k` (see below). Decrypting a file whose name doesn't end in `.aes` needs
`-o`. `--iterations` sets the PBKDF2 work factor when encrypting (default
300,000).

## Passwords

There is deliberately **no option or environment variable that takes a
password.** Command-line arguments are visible to every user through `ps` and
end up in shell history. Environment variables leak into child processes,
crash reports and CI logs. This follows [age](https://github.com/FiloSottile/age).

A password comes from one of three places:

- **The terminal (default).** You're asked twice when encrypting and once when
  decrypting. The prompt reads the terminal directly, so piping data through
  stdin still works. When encrypting, a password shorter than 12 characters
  gets a warning.
- **`--password-command CMD`**, for scripts and password managers. The
  command's output, minus one trailing newline, is the password:

  ```sh
  aescrypt-cli -d --password-command 'pass show backups/aes' backup.tar.aes
  ```

  The command runs through `sh -c` (`cmd /S /C` on Windows, which receives it
  exactly as written, quotes included), with stdin closed so
  it can't consume data piped to aescrypt-cli. Its stderr is shown.
- **`--password-file PATH`**, when quoting a command is more trouble than it's
  worth. The file's contents, minus one trailing newline, are the password; no
  shell is involved. A leading UTF-8 byte order mark, which Windows PowerShell
  5.1 adds with `Out-File` and `Set-Content -Encoding UTF8`, is ignored, here
  and in `--password-command` output. On Unix, `--password-file <(pass show backups/aes)` keeps
  the password off disk. Files over 64 KiB are refused as almost certainly the
  wrong path, and on Unix a file other users can read draws a warning. No
  output may replace the password file, even with `--force`.

`--password-command` and `--password-file` never ask for confirmation and never
generate a passphrase. Only one of them can be given.

### Generated passphrases

Leave the password prompt empty when encrypting and aescrypt-cli generates a
passphrase for you, such as `k7qd-m2xa-r4vn-…`: 160 random bits as 32
lowercase base32 characters in groups of four. It is printed once, to the
terminal, and stored nowhere. This only happens when stderr is a terminal, so a
generated passphrase can't end up in a log file.

## Safety

- **No partial or unverified output.** The AES Crypt format can only be
  verified once the whole file has been read. aescrypt-cli therefore writes to
  a `.aescrypt-cli-*.tmp` file next to the destination (hidden by its name on
  Unix; visible on Windows while it runs), and renames it
  into place only after decryption has been verified. A wrong password or a
  damaged file leaves nothing behind. One exception is in the format itself:
  in v0–v2 files, the byte that records how long the last block is isn't
  covered by the integrity check, so if only that byte is damaged, the file
  still decrypts, and the output can be up to 15 bytes too short or too long.
  v3 files, which aescrypt-cli writes, check it.
- **Decrypting to stdout** stages the plaintext in the system temp directory
  and only copies it out after verification. Nothing unverified reaches a
  pipe. This needs temporary disk space equal to the file's size.
- **Ctrl-C, `kill`, or closing the terminal** deletes any in-progress temp
  file. At the password prompt it exits immediately and turns terminal echo
  back on, on Windows as well as Unix. A forced kill can't be caught, so it
  leaves the temp file behind: `kill -9` on Unix, and `taskkill /F` or
  `Stop-Process` on Windows. Delete any leftover `.aescrypt-cli-*.tmp` file
  by hand. The destination is never touched: nothing has been renamed into
  place yet.
- **Crash safety.** Output is flushed to disk before it's renamed, so a crash
  can't leave an empty file under the final name.
- **No overwriting.** An existing output file is never replaced without
  `--force`. An output that is the same file as the input is always refused,
  including through hard links and symlinks. In a run with several files, an
  output that is one of the other inputs, or another file's output, is refused
  too, even with `--force`. One gap: on a case-insensitive filesystem (the
  Windows and macOS defaults), two new outputs whose names differ only in case
  aren't caught in advance. Without `--force` the second is refused; with it,
  the second replaces the first one's output. No input is touched either way.
- **No ciphertext on a terminal.** Encrypting to stdout is refused when stdout
  is a terminal.

### File permissions

On Unix, decrypted files are created readable and writable by you only
(`0600`), on filesystems that store Unix permissions. Some don't, and there
the mount decides: a Windows drive under WSL (`/mnt/c`), FAT and exFAT
drives, and network shares mounted without Unix extensions. Decrypted files
there can come out readable by everyone (`/mnt/c` gives `0777`). On Windows,
decrypted files inherit the folder's permissions, like any new file. On
those filesystems and on Windows, decrypt into a folder only you can read.
Encrypted files get the normal permissions your umask gives new files.

`--force` replaces the old file rather than writing into it, so the
replacement doesn't keep the old file's owner, permissions or hard links.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | every file succeeded |
| 1 | at least one file failed (each failure is reported; other files still run), or no password could be obtained, in which case no file was processed (confirmation mismatch, empty password, `--password-command` or `--password-file` failure, no terminal) |
| 2 | invalid command line |
| 3 | every file that failed was decrypted with the wrong password, so another password may work (for a v0 file this can also mean the file is damaged; v0 cannot tell them apart) |
| 130 | interrupted (Ctrl-C, SIGTERM, or the terminal closed) |

## Non-goals

- **Deleting or shredding the original after encrypting.** Secure deletion is
  unreliable on SSDs and copy-on-write filesystems, so offering it would give
  false comfort.
- **Encrypting folders.** Use `tar`, as in the table above.
- **Different passwords for different files in one run.** One password covers
  the whole run. Run files with different passwords separately.
- **Unicode normalization of passwords.** It would break compatibility with
  other AES Crypt tools. One trap: macOS can type an accented character such as
  `é` in a different internal form than Linux or Windows, so a password that
  looks identical may fail to decrypt on another machine. Plain ASCII
  passwords, and generated passphrases, are unaffected.
- **Locking memory or disabling core dumps.** The password is moved into a
  wipe-on-drop container as soon as aescrypt-cli has it in one piece. Copies
  made before that are not wiped: buffers inside the terminal, the prompt
  library's buffer as it grows, the buffers `--password-command` output
  passes through while it is read, and the operating system's cached copy of
  a `--password-file`.
- **A progress bar and shell completions**, for now.

## Versioning

Until `aescrypt-rs` 0.2.0 is released, aescrypt-cli carries the same version
number as the library it's built with. `aescrypt-cli --version` shows both.

## License

MIT OR Apache-2.0, at your option.
