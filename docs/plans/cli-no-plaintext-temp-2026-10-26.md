# aescrypt-cli: no plaintext in temp files that get thrown away (#72)

**Status (2026-10-26, UTC):** built, in the PR that adds this file; it lands before
aescrypt-cli 0.1.0-rc.4 is cut. Found by the external review of aescrypt-rs `v0.2.0-rc.16`
(`.agent/rc16/audit-01.md`, finding 3, Low). The problem predates rc.16. Tracking: issue #72.
Verified at main `58e61d0`.

## Measured state (before)

- **Decrypt to stdout** (`execute`, `aescrypt-cli/src/lib.rs`): the whole plaintext was staged
  in a temp file under the system temp directory, then `copy_to`'d out and unlinked without
  being overwritten.
- **Decrypt from stdin:** stdin cannot seek, so it ran the one-pass `decrypt`. That wrote
  unverified plaintext into the stage, which was deleted on failure.
- **Every stage** was written through an 8 KiB `BufWriter`, whose buffer was not wiped.
  `copy_to`'s `io::copy` buffer held a chunk of plaintext.
- **Ctrl-C** (`signals.rs`) and drop only unlink. Windows delete-on-close and Linux `O_TMPFILE`
  remove the name on a forced kill, not the bytes.

## Target model

**No plaintext is written to a temp file that is then thrown away.** Plaintext reaches disk
only as the output itself. That is the temp file next to a file destination, renamed into
place, and it is written only in `decrypt_verified`'s second pass, after verification.

Overwriting before unlinking was rejected. It is unreliable on SSDs (wear levelling) and on
copy-on-write filesystems; not writing the plaintext at all is the only dependable fix.

## Change

1. **stdin decrypt:** `stage_ciphertext` copies stdin's ciphertext into a staged temp file and
   rewinds it. The stage goes next to the destination, or in the system temp directory for
   stdout. It is then decrypted with `decrypt_verified`, like a file (`Input::Staged`). A
   tampered or truncated stdin now writes nothing.
2. **Decrypt to stdout:** written straight to stdout in pass 2. There is no plaintext stage,
   and `copy_to` is removed.
3. **Stages are written through their `File`** (`Staged::file`), with no `BufWriter`. The
   library already writes 64 KiB spans.
4. **`crypt`** sends every decryption through `decrypt_verified`. The one-pass `decrypt` is no
   longer used by the CLI.

## Acceptance

- **No plaintext stage.** No code path writes plaintext to a temp file other than the output
  itself.
- **The new guards fail when broken.** Tests: `tampered_stdin_input_writes_nothing`,
  `stdin_stage_holds_the_ciphertext`, `stdin_decrypts_verified_to_stdout_and_file`, and stdin
  cases added to `tampered_file_leaves_no_output`. Falsified once: decrypting the staged stdin
  one-pass again fails both the unit test and the end-to-end test ("100000 unverified bytes
  from stdin reached stdout").
- **Existing tests pass:** the kill and Ctrl-C temp-file tests, the official vectors, and the
  failure descriptions.

## Residue, stated rather than fixed

- **The standard library's stdout buffer** holds small writes. That buffer is not ours to wipe.
- **Pass-2 failures.** A read or write error during pass 2 can leave partial, verified output
  on stdout, or in the destination's temp file, which is then deleted.
- **Disk space.** stdin decryption needs temporary disk space for the ciphertext.
