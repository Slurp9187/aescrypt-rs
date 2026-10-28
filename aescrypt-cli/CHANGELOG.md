# Changelog

All notable changes to `aescrypt-cli` are documented in this file. The library
has its own changelog in `../CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versioned independently of `aescrypt-rs`; `--version` shows both.

## [0.1.0-rc.5] - Unreleased

### Changed

- Built on `aescrypt-rs` 0.2.0-rc.17.
- Decrypting to stdout is about twice as fast. The sealed temp file it goes
  through is now sealed and read back 64 KiB at a time instead of 4 KiB, in two
  buffers made once per file and wiped as before. Decrypting a 1 GiB file to
  stdout took 2.1–2.7 s instead of 4.4–5.0 s, about as long as decrypting to a
  file (one high-end desktop, Ryzen 9 9950X3D with AES-NI; output discarded).
  Nothing else changes: the seal, its key, and the all-or-nothing output.

## [0.1.0-rc.4] - 2026-10-26

### Changed

- Built on `aescrypt-rs` 0.2.0-rc.16 (was 0.2.0-rc.13), which this release pins
  exactly, so `aescrypt-rs` 0.2.0-rc.16 must be published first. That library now
  reads, encrypts or decrypts, and writes 64 KiB at a time instead of 16 bytes
  (aescrypt-rs #68). On its 64 MiB benchmark, decrypting is about three times as fast,
  and so is the verified decrypt this CLI uses for input files. The files it writes
  are byte-for-byte the same.
  - Decrypting now holds about 128 KiB of memory, still the same for any file size.
  - Encrypting from a slow pipe to stdout now emits ciphertext 64 KiB at a time
    (before, the CLI's 8 KiB output buffer set the pace). Every other output is
    staged until the run finishes, so it is unaffected.
- `secure-gate` is pinned to `=0.9.0-rc.15` (was `=0.9.0-rc.12`), matching
  `aescrypt-rs`, so a build that uses both carries one copy. 0.1.0-rc.3 is the last
  published crate that still pins `=0.9.0-rc.12`.
- `--version` reads the library's version from `aescrypt_rs::VERSION`, so it always names
  the `aescrypt-rs` this build linked. It was a copy kept by hand in the CLI's source,
  which every library bump had to edit. The output is unchanged in form.

### Fixed

- **Plaintext is no longer written to temp files that get thrown away** (#72).
  - **Decrypting to stdout** used to stage the whole plaintext in the clear in the
    system temp directory, copy it out, then delete the file without overwriting
    it. The stage is now *sealed*: AES-256-CTR under a random key held only in
    memory, unsealed while it is copied to stdout once the whole decryption has
    succeeded. A failure, Ctrl-C or a changed input during decryption writes nothing
    to stdout, and the disk only ever holds noise. Only the copy itself, once begun,
    can be cut short by a signal or a write error.
  - **Decrypting from stdin** used to run the one-pass decrypt, writing unverified
    plaintext to a temp file that was deleted on failure. It now stages stdin's
    *ciphertext* in an owner-only temp file (next to the destination, or in the
    temp directory for stdout) and decrypts it verify-first, like a file. A
    tampered or truncated stdin now writes nothing at all. A failure to write the
    stage, such as a full disk, is reported against its folder, not against stdin.
  - **Buffers:** plaintext is written to its temp file without a `BufWriter`,
    whose buffer kept an unwiped copy of the last plaintext it held. The library
    writes whole spans. Ciphertext sides (encrypting, reading a staged stdin)
    stay buffered.
  - **Still outside the CLI's reach:** the standard library's own stdout buffer,
    which holds small writes. When decrypting to a *file*, an I/O error, a
    changed input or a signal during the verified second pass can leave verified
    plaintext in the destination's temp file, which is deleted without being
    overwritten; that file is the output itself, so it cannot be sealed.

### Removed

- The hidden `LIB_VERSION` constant, the copy `--version` used to read. It was
  `#[doc(hidden)]`, and this crate's library target is not an API.

## [0.1.0-rc.3] - 2026-10-15

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
