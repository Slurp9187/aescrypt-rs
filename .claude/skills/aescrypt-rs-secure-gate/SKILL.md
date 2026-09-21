---
name: aescrypt-rs-secure-gate
description: Handling key material in aescrypt-rs with secure-gate wrappers — the Fixed-dominant alias set in aliases.rs, the SpanBuffer generic, and the streaming public API that keeps plaintext out of any return value. Use when touching the KDFs, the session block, the decryption ring buffer, or the header/extension readers; or when adding an alias. Not for file version bytes, extension payload structure, or error messages.
---

# secure-gate in aescrypt-rs

**Sole authority for this topic.**

The protocol — access tiers, the residue hazards, Fixed vs Dynamic, alias vs newtype, the
reveal-borrow defect, the exact-pin argument — is in the global `secure-gate` skill. **This
file records only what is true of this crate.**

## Dependency

```toml
secure-gate = { version = "=0.9.0-rc.12", features = ["rand", "ct-eq"] }
```

**Pinned, and the reasoning is already in `Cargo.toml` rather than here** — including the
`"0.9"`-resolves-to-nothing trap and the rule that a published requirement travels to
dependents while a lockfile does not. Do not duplicate it; read it there.

**The same line appears character-identically in `fuzz/Cargo.toml`.** Keep it that way: the
fuzz crate depends on this one, so a drift between the two produces two secure-gate versions in
one graph. Bumping means changing both pins and running `cargo update -p secure-gate` in
**both** lockfiles.

**Every rule in the global skill is read against rc.12.** This crate declares no newtypes, so
the rc.13 `derive: [ConstantTimeEq]` break does not hit it — but the bump is a coordinated
ecosystem wave, since several first-party crates pin exactly and two different exact
requirements in one compatibility range cannot resolve.

## Fixed-dominant, and that is the format's doing

Where the sibling crates are almost entirely `Dynamic`, this one is almost entirely `Fixed` —
**because AES Crypt fixes every size in the spec.** There is no `keyBits` attribute to read and
no manifest to trust: a session key is 32 bytes because the format says so.

That makes this crate the clean demonstration of the rule from the other side. *Reach for
`Fixed` when the byte count is fixed by your own design or by a spec you implement; reach for
`Dynamic` when it is fixed by input you do not control.* Here only the password qualifies.

`src/aliases.rs`:

| Alias | Type | Holds |
|---|---|---|
| `PasswordString` | `Dynamic<String>` | the only value whose length the user decides |
| `AckdfDerivedKey32` | `Fixed<[u8; 32]>` | ACKDF-derived v0/v1/v2 setup key |
| `Pbkdf2DerivedKey32` | `Fixed<[u8; 32]>` | PBKDF2-derived v3 setup key |
| `Aes256Key32` | `Fixed<[u8; 32]>` | session key, HMAC key |
| `EncryptedSessionBlock48` | `Fixed<[u8; 48]>` | encrypted session IV + key |
| `SessionHmacTag32` | `Fixed<[u8; 32]>` | session block HMAC |
| `Iv16` | `Fixed<[u8; 16]>` | public IV, session IV |
| `Salt16` | `Fixed<[u8; 16]>` | PBKDF2/ACKDF salt |
| `RingBuffer64` | `Fixed<[u8; 64]>` | streaming decryption ring buffer |

Plus a **generic** alias and four built on it:

```rust
pub type SpanBuffer<const N: usize> = secure_gate::Fixed<[u8; N]>;
pub type AckdfHashState32  = SpanBuffer<32>;
pub type Block16           = SpanBuffer<16>;   // one AES block
pub type ExtensionChunk256 = SpanBuffer<256>;  // v2/v3 extension payload chunk
pub type Trailer32         = SpanBuffer<32>;   // v0/v3 HMAC trailer
```

`SpanBuffer` is **the hand-written replacement for `fixed_generic_alias!`**, which secure-gate
deleted in rc.9 along with the other three alias macros. The migration for that form is exactly
this line — see the global skill's *upgrade* reference. Nothing here needs to change.

`HmacSha256` in the same file is `Hmac<Sha256>`, not a secure-gate type. Do not count it.

**These are `type` aliases, so same-shaped ones are the same nominal type.** Five distinct
32-byte roles — two derived keys, a session key, a hash state and an HMAC tag — are mutually
substitutable, and `Iv16`/`Salt16` likewise at 16. That is past the point where the global skill
says to settle the newtype question. Nothing has yet passed the wrong one; record it as a
deliberate open choice rather than an oversight, and revisit when a sixth 32-byte role appears.

## Boundary — streaming, so plaintext has no return value to escape through

```rust
pub fn encrypt<R, W>(input: R, output: W, password: &str, ...) -> Result<(), AescryptError>
pub fn decrypt<R, W>(input: R, output: W, password: &str)      -> Result<(), AescryptError>
```

The password is a plain `&str` — **deliberately**, and it is what decoupled this crate from its
consumers: while a wrapper sat in that signature, every consumer had to depend on secure-gate
and match its exact pin. Removing it is the reason this crate and its consumers can now move
independently.

And because both directions stream through `R`/`W`, **the plaintext never materializes as a
returned buffer at all** — the shape the sibling crates have to argue about (*wrapping the
returned `Vec<u8>` would be ceremony*) simply does not arise here.

### ⚠️ But the wrappers are public anyway, through the modules

`lib.rs` has `pub mod aliases;` and `pub mod decryption;`, so `SpanBuffer` and friends are part
of the public API, and `read_exact_span<R, const N: usize> -> SpanBuffer<N>` is a public
function returning a wrapper. The curated re-exports (`encrypt`, `decrypt`, `AescryptError`,
`Pbkdf2Builder`, `derive_ackdf_key`, `derive_pbkdf2_key`) are clean; the module surface is not.

So the boundary is clean where it is *used* and leaky where it is *reachable*. That is a real
position, not a bug, but it should be a decided one: either the modules are genuinely public
API and the wrapper exposure is accepted and documented, or they should be `pub(crate)` with
the useful pieces re-exported. **Do not leave it implied.**

## Tier 1 only

Measured in `src/` (files, not occurrences):

```sh
for m in with_secret with_secret_mut expose_secret into_inner from_random new_with ct_eq; do
  printf '%-16s %s\n' "$m" "$(grep -rl "$m" --include=*.rs src/ | wc -l)"
done
```

| method | files |
|---|---|
| `with_secret` | 15 |
| `with_secret_mut` | 9 |
| `from_random` | 4 |
| `ct_eq` | 3 |
| `new_with` | 2 |
| `expose_secret` | **0** |
| `into_inner` | **0** |

**No Tier 2 and no Tier 3.** Keep it that way — the first `expose_secret` is a decision to
argue for, not a convenience.

**`with_secret_mut` in 9 files is safe here, and the reason is structural.** The global skill
warns that `with_secret_mut` on a *growable* wrapper hands out a raw `&mut Vec` whose growth
abandons the old buffer unwiped. Every mutable borrow in this crate is on a `Fixed`, which
**cannot reallocate** — the ring buffer, the derived keys, the block buffers. The one `Dynamic`
is `PasswordString`, and nothing mutates it.

That immunity is a property of the *alias set*, not of the code. **If a `Dynamic` alias is ever
added and then mutated, the carve-out stops applying** — check the global skill before writing
the first one.

The idiomatic shape here nests, which keeps both operands scoped:

```rust
salt.with_secret(|s| {
    out_key.with_secret_mut(|key| pbkdf2::<Hmac<Sha512>>(password.as_bytes(), s, iterations, key))
})
```

`password.as_bytes()` borrows the caller's buffer in place — no copy is made, so there is
nothing extra for that function to zeroize.

## Public values wrapped on purpose

`Iv16` and `Salt16` hold values written into the file header in the clear. They are wrapped
anyway, for type-level length enforcement, redacted `Debug`, and a greppable name that ties
them to the key material they participate with.

That is the policy fork the global skill names, and it is **not free**: `Drop` is
unconditional, so every one of them is memset on drop. The auditability argument stands on its
own; do not restate it as "zero-cost".

## Deliberately not wrapped

- **`password: &str` at the public boundary** — the caller owns it.
- **File version bytes, extension payload structure, KDF iteration counts** — header fields,
  public by construction, read straight out of the file.
- **Error messages.** Describe the failure, never the data.

## Residue

Re-derive from the manifests rather than trusting a sibling's list. The general shape applies:
the `Sha256`/`Sha512` hashers buffer their input until `finalize` and drop unzeroized, and the
compression functions spill a message schedule. `sha2` at 0.10 exposes no `zeroize` feature.
The fix is upstream — **do not reimplement a hash here.**

`aescrypt-rs` is a **library**, so it does not install a zero-on-deallocate global allocator and
must not. It points its consumers at the `heap-residue` skill instead.

## Enforcement

CI is `fuzz.yml` and `msrv.yml` — **neither knows about wrapper discipline.** Tier usage,
coverage and the reveal-borrow shape are caught in review only. The fuzz suite is real coverage
of the parsing surface and no coverage at all of this.

## Changelog

Already conforms to the canonical `## [0.2.0-rc.11] - 2026-09-15` format — brackets, ASCII
hyphen, ISO date, no `v` prefix — and passes the global checker clean, with every dated heading
tagged. No local changelog profile is needed; the global `changelog-protocol` skill applies
as-is.

⚠️ One audit trap worth knowing: **`git tag -l` sorts lexically**, so `v0.2.0-rc.10` and
`v0.2.0-rc.11` sort *before* `v0.2.0-rc.9`. A `| tail -3` reads as though the newest releases
are untagged when they are not. Use the checker, or sort by version.

## Verify

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo +<msrv> check --locked          # the msrv job
```

After a secure-gate bump, both lockfiles: this crate's and `fuzz/Cargo.lock`.

## What did not transfer

- **The "wrapping the returned plaintext would be ceremony" argument.** Both directions stream,
  so there is no returned plaintext to argue about.
- **The `Dynamic`-heavy guidance** — realloc residue, `try_new_with`, sized-slot construction.
  One `Dynamic` here and nothing mutates it. Re-read that section the moment a second appears.
- **The bare `[Unreleased]` and heading-format migration notes** in the changelog skill. This
  crate already conforms.
