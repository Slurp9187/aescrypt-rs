# Changelog

All notable changes to `aescrypt-cli` are documented in this file. The library
has its own changelog in `../CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versioned independently of `aescrypt-rs`; `--version` shows both.

## [0.1.0-rc.3] - Unreleased

### Fixed

- A forced kill (`kill -9`, `taskkill /F`, `Stop-Process -Force`) no longer leaves the
  staged temp file, which could hold plaintext, on Windows or Linux (#64). No process
  can catch those, so the operating system now deletes the temp file itself when the
  process dies:
  - on Windows, the file is opened delete-on-close and given its final name with a hard
    link;
  - on Linux, it's an unnamed `O_TMPFILE`, given its name with `linkat`.

  Both use safe APIs; the CLI still forbids `unsafe`. Without `--force` an existing
  output is still never replaced. A filesystem that refuses (FAT has no hard links, some
  network filesystems have no `O_TMPFILE`) falls back to the previous named temp file.
  macOS still leaves the temp file after a forced kill.

## [0.1.0-rc.2] - 2026-10-15

### Changed

- The `--iterations` default now comes from the library's `DEFAULT_PBKDF2_ITERATIONS`
  instead of a copy in the CLI. The value is unchanged at 600,000; the CLI kept its own
  only because `aescrypt-rs` 0.2.0-rc.11 still defaulted to 300,000.
- Built on `aescrypt-rs` 0.2.0-rc.13 (was 0.2.0-rc.12), which this release pins
  exactly, so `aescrypt-rs` 0.2.0-rc.13 must be published first.
- Decrypting an input file now checks its integrity before writing any plaintext
  (#59). The file is read twice, through the library's `decrypt_verified`. A wrong
  password, a damaged or tampered file, or invalid padding now writes no plaintext at
  all. Before, the plaintext went into the staging temp file and was deleted when the
  check failed; the destination was never touched. Decrypting a large file takes about
  twice the reading time. Decrypting from stdin (`-`) still reads once, because a pipe
  can't be read twice, and its output is still staged and discarded on failure. A new
  message, "the file changed while it was being decrypted; no output was kept", covers a
  file that changes between the two reads (exit code 1).

## [0.1.0-rc.1] - 2026-10-12

### Added

- First release: `aescrypt-cli -e|-d [-o OUTPUT] [--force] [--iterations N]
  [--password-command CMD | --password-file PATH] FILE...`, decrypting AES Crypt
  v0–v3 and encrypting v3. Built on `aescrypt-rs` 0.2.0-rc.12.
- `--iterations` defaults to 600,000, the official AES Crypt tool's default.
  Files interoperate with the official tool (4.7) in both directions.
- Passwords come from a terminal prompt, `--password-command` or
  `--password-file`, never from a flag or an environment variable. An empty
  answer at the encrypt prompt generates a 160-bit passphrase.
- Output is staged in a temp file and renamed into place only after
  verification, so failures leave nothing behind. Decrypting to stdout also
  waits for verification. Ctrl-C deletes in-progress temp files.
- Existing files are never overwritten without `--force`. An output that is the
  same file as any input of the run, or as another file's output, is refused
  even with `--force` (except two new outputs whose names differ only in case,
  on a case-insensitive filesystem; see the README).
- Exit codes: 0 success, 1 a file failed (or no password could be obtained),
  2 usage error, 3 every failure was a wrong password, 130 interrupted.
