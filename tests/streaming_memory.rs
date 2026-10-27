//! `tests/streaming_memory.rs`
//! `decrypt_verified` and `decrypt` run in memory that does not grow with the
//! file (#58).
//!
//! A test binary of its own, because it installs a counting global
//! allocator, and one `#[test]`, so no other test allocates while it
//! measures. Each size is encrypted from a pattern reader to a temporary
//! file, then decrypted from a `BufReader<File>` to a sink that checks every
//! byte against the pattern and keeps none. Peak heap growth during the
//! decrypt must stay under a fixed bound at every size.

// Test crate: helpers and fixtures are explained by the tests that use them.
#![allow(clippy::missing_docs_in_private_items)]

use aescrypt_rs::{decrypt, decrypt_verified, encrypt};
use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to `System` unchanged; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Heap growth allowed during one decrypt, whatever the file size: the two
/// boxed 64 KiB spans the loop decrypts between (#68; 131 056 bytes measured),
/// plus 64 KiB for the I/O error paths and anything the standard library
/// allocates lazily. The `BufReader` is created before measuring.
const BOUND: usize = 2 * 64 * 1024 + 64 * 1024;

const MIB: u64 = 1024 * 1024;

fn pattern(i: u64) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 9)) as u8
}

/// Reads `len` bytes of the pattern without holding them.
struct PatternReader {
    pos: u64,
    len: u64,
}

impl Read for PatternReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (self.len - self.pos).min(buf.len() as u64) as usize;
        for (k, b) in buf[..n].iter_mut().enumerate() {
            *b = pattern(self.pos + k as u64);
        }
        self.pos += n as u64;
        Ok(n)
    }
}

/// Checks each byte against the pattern and keeps nothing.
struct PatternCheck {
    pos: u64,
}

impl Write for PatternCheck {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for (k, b) in buf.iter().enumerate() {
            assert_eq!(
                *b,
                pattern(self.pos + k as u64),
                "byte {}",
                self.pos + k as u64
            );
        }
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Runs `f` and returns the peak heap growth above the level when it started.
fn peak_growth(f: impl FnOnce()) -> usize {
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    f();
    PEAK.load(Ordering::SeqCst) - base
}

#[test]
fn decrypt_memory_does_not_grow_with_the_file() {
    let sizes: &[u64] = if std::env::var_os("AESCRYPT_MEMORY_TEST_LARGE").is_some() {
        &[64 * MIB, 256 * MIB]
    } else {
        &[MIB, 64 * MIB]
    };

    for &len in sizes {
        let path = std::env::temp_dir().join(format!(
            "aescrypt-rs-streaming-memory-{}-{len}.aes",
            std::process::id()
        ));
        {
            let mut out = BufWriter::new(File::create(&path).unwrap());
            encrypt(PatternReader { pos: 0, len }, &mut out, "pw", 1).unwrap();
            out.flush().unwrap();
        }

        let mut input = BufReader::new(File::open(&path).unwrap());
        let mut check = PatternCheck { pos: 0 };
        let mut outcome = None;
        let verified = peak_growth(|| {
            outcome = Some(decrypt_verified(&mut input, &mut check, "pw").unwrap());
        });
        assert_eq!(check.pos, len);
        assert_eq!(outcome.unwrap().plaintext_len, len);

        let mut input = BufReader::new(File::open(&path).unwrap());
        let mut check = PatternCheck { pos: 0 };
        let one_pass = peak_growth(|| decrypt(&mut input, &mut check, "pw").unwrap());
        assert_eq!(check.pos, len);

        std::fs::remove_file(&path).unwrap();

        eprintln!(
            "{} MiB: peak heap growth decrypt_verified {verified} B, decrypt {one_pass} B",
            len / MIB
        );
        assert!(
            verified <= BOUND,
            "decrypt_verified grew {verified} B at {len} B"
        );
        assert!(one_pass <= BOUND, "decrypt grew {one_pass} B at {len} B");
    }
}
