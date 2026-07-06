#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|case: aescrypt_rs_fuzz::LegacyCase| aescrypt_rs_fuzz::fuzz_roundtrip_legacy(&case));
