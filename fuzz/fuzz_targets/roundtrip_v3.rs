#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|case: aescrypt_rs_fuzz::V3Case| aescrypt_rs_fuzz::fuzz_roundtrip_v3(&case));
