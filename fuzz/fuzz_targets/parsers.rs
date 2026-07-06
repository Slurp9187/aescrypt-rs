#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| aescrypt_rs_fuzz::fuzz_parsers(data));
