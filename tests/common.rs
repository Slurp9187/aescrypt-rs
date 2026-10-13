//! `tests/common.rs`
//! Common constants and utilities shared across test files

// Test crate: helpers and fixtures are explained by the tests that use them.
#![allow(clippy::missing_docs_in_private_items)]

/// Fast iteration count for tests - performance testing is in `benches/`
/// Most tests use this value to keep test execution fast.
pub const TEST_ITERATIONS: u32 = 5;

/// Standard test password used across test vectors and test files
/// Matches the password used in the `test_data/` test vectors and `.aes` files
#[allow(dead_code)] // Used across multiple test files
pub const TEST_PASSWORD: &str = "Hello";

/// Common test data strings used across multiple tests
#[allow(dead_code)] // Used across multiple test files
pub const TEST_DATA: &[u8] = b"test data";

/// A 4-byte plaintext, shorter than one AES block
#[allow(dead_code)] // Used across multiple test files
pub const TEST_DATA_SHORT: &[u8] = b"test";

/// Common iteration count vectors for testing various iteration values
#[allow(dead_code)] // Used across multiple test files
pub const TEST_ITERATION_VALUES: &[u32] = &[1, TEST_ITERATIONS, 10];
