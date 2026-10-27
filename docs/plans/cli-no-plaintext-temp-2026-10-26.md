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

**Plaintext never reaches a temp file in the clear, other than the output itself.** For a
file destination, the output is the temp file next to it, renamed into place, and it is
written only in `decrypt_verified`'s second pass, after verification. Decrypting to stdout
stays all-or-nothing through decryption: Ctrl-C, a kill or a changed input during it writes
nothing to the pipe. The copy to stdout, once begun, can still be cut short by a signal or a
write error; that window is inherent.

Overwriting before unlinking was rejected. It is unreliable on SSDs (wear leveling) and on
copy-on-write filesystems; not writing the plaintext at all is the only dependable fix.

## Change

1. **stdin decrypt:** `stage_ciphertext` copies stdin's ciphertext into a staged temp file and
   rewinds it. The stage goes next to the destination, or in the system temp directory for
   stdout. It is then decrypted with `decrypt_verified`, like a file (a `ReadSeek` input). A
   tampered or truncated stdin now writes nothing.
2. **Decrypt to stdout: a sealed stage** (`output::Sealed`). Pass 2's plaintext is written
   through AES-256-CTR under a random key held only in memory (a `secure_gate::Fixed`), into
   an owner-only temp file. `copy_out` unseals it to stdout only after the whole call has
   succeeded. This is EFV's `SealedScratch` pattern.
   - **As first built**, PR #74 wrote straight to stdout in pass 2. `/code-review` found that
     this lost the all-or-nothing guarantee: Ctrl-C, SIGTERM or a changed input during pass 2
     left truncated or unverified output on stdout. The owner chose the sealed stage.
   - **It uses the same `aes` crate as the library**, so nothing new enters the graph.
   - **No integrity on the seal.** Someone who can write the temp file while it runs could
     flip output bits, exactly as with the plaintext stage it replaces.
3. **Plaintext is written unbuffered.** The output stage is written through its `File`
   (`Staged::file`) and the sealed stage in 4 KiB wiped chunks, never through a `BufWriter`.
   Ciphertext sides are buffered: encrypt output, and reads of the staged stdin.
4. **Encrypt and decrypt are separate paths:** `encrypt_with` takes a `VersionTap<Box<dyn
   Read>>`, and `decrypt_with` takes a `VersionTap<Box<dyn ReadSeek>>`. The one-pass `decrypt`
   is no longer used by the CLI, and no input/mode pairing is left to an `unreachable!()`.
5. **Every stage that is not the output is owner-only:** stdin's ciphertext and the sealed
   stage. `stage_ciphertext` reports read errors against `<stdin>` and write errors against
   the stage's folder.

## Acceptance

- **No plaintext stage.** No code path writes plaintext to a temp file other than the output
  itself.
- **The new guards fail when broken.** Tests: `tampered_stdin_input_writes_nothing`,
  `stdin_stage_holds_the_ciphertext` (which also checks owner-only on Unix),
  `stdin_decrypts_verified_to_stdout_and_file`, stdin cases added to
  `tampered_file_leaves_no_output`, and for the sealed stage:
  `sealed_stage_round_trips_and_holds_no_plaintext`, `sealed_stages_have_their_own_keys` and
  `dropped_stages_leave_nothing`. Falsified once: decrypting the staged stdin
  one-pass again fails both the unit test and the end-to-end test ("100000 unverified bytes
  from stdin reached stdout").
- **Existing tests pass:** the kill and Ctrl-C temp-file tests, the official vectors, and the
  failure descriptions.

## Residue, stated rather than fixed

- **The standard library's stdout buffer** holds small writes. That buffer is not ours to wipe.
- **Pass-2 failures with a file destination.** An I/O error, a changed input or a signal
  during pass 2 can leave verified plaintext in the destination's temp file, which is deleted
  unwiped. That file is the output itself, so it cannot be sealed.
- **Disk space.** stdin decryption needs temporary disk space for the ciphertext.
