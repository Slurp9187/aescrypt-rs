//! tests/common.rs
//! Common constants and utilities shared across test files

/// Fast iteration count for tests - performance testing is in benches/
/// Most tests use this value to keep test execution fast.
pub const TEST_ITERATIONS: u32 = 5;

/// Standard test password used across test vectors and test files
/// Matches the password used in test_data/ test vectors and .aes files
#[allow(dead_code)] // Used across multiple test files
pub const TEST_PASSWORD: &str = "Hello";

/// Common test data strings used across multiple tests
#[allow(dead_code)] // Used across multiple test files
pub const TEST_DATA: &[u8] = b"test data";

#[allow(dead_code)] // Used across multiple test files
pub const TEST_DATA_SHORT: &[u8] = b"test";

/// Common iteration count vectors for testing various iteration values
#[allow(dead_code)] // Used across multiple test files
pub const TEST_ITERATION_VALUES: &[u32] = &[1, TEST_ITERATIONS, 10];

