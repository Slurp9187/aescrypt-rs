# Changelog

All notable changes to `aescrypt-cli` are documented in this file. The library
has its own changelog in `../CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until `aescrypt-rs` 0.2.0, versions mirror the library's.

## [0.2.0-rc.11] - 2026-10-12

### Added

- First release: `aescrypt-cli -e|-d [-o OUTPUT] [--force] [--iterations N]
  [--password-command CMD | --password-file PATH] FILE...`, decrypting AES Crypt
  v0–v3 and encrypting v3.
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
