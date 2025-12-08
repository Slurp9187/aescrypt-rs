# Test Vectors and Test Files

This directory contains test vectors and encrypted test files for the `aescrypt-rs` library.

## Test Parameters

All test vectors and encrypted files in this directory use the following parameters:

- **Password**: `"Hello"`
- **PBKDF2 Iterations**: `5`

These low iteration counts are used to keep tests fast. Performance testing with higher iteration counts is done in the `benches/` directory.

## Test Vectors (JSON Files)

The JSON files contain known plaintext/ciphertext pairs for cryptographic verification:

- `test_vectors_v0.json` - AES Crypt v0 format test vectors (21 vectors)
- `test_vectors_v1.json` - AES Crypt v1 format test vectors (21 vectors)
- `test_vectors_v2.json` - AES Crypt v2 format test vectors (21 vectors)
- `test_vectors_v3.json` - AES Crypt v3 format test vectors (21 vectors)
- `deterministic_test_vectors_v3.json` - Deterministic v3 test vectors (42 vectors)

Each JSON file contains an array of objects with:
- `plaintext`: The original unencrypted data (string)
- `ciphertext_hex`: The encrypted data in hexadecimal format (string)

These vectors are used by multiple test files:
- `tests/vector_tests.rs` - Vector-based encryption/decryption tests
- `tests/convert_tests.rs` - Legacy conversion tests
- `tests/header_tests.rs` - Header parsing tests
- `tests/file_ops_tests.rs` - File I/O tests

## Encrypted Test Files (.aes)

The `aes_test_files/` directory contains actual encrypted files generated from the test vectors.

**Location**: This directory is at `tests/test_data/` (top-level in tests) because it's shared across multiple test files, not just vector tests.

### Structure

- `v0/` - 21 encrypted files (v0_test_00.txt.aes through v0_test_20.txt.aes)
- `v1/` - 21 encrypted files (v1_test_00.txt.aes through v1_test_20.txt.aes)
- `v2/` - 21 encrypted files (v2_test_00.txt.aes through v2_test_20.txt.aes)
- `v3/` - 42 encrypted files:
  - 21 regular files (v3_test_00.txt.aes through v3_test_20.txt.aes)
  - 21 deterministic files (v3_deterministic_00.txt.aes through v3_deterministic_20.txt.aes)

These files are used by `tests/file_ops_tests.rs` for integration testing of:
- Direct file decryption
- File-based conversion/upgrade (v0/v1/v2 → v3)
- Password rotation
- Batch operations
- Real-world file I/O scenarios

## Generation Scripts

The `scripts/` directory contains Python scripts used to generate these test files:

- `generate_test_files_all_versions.py` - Generates all test files for all versions
- `generate_v0_test_files.py` - Generates v0 test files
- `generate_v1_test_files.py` - Generates v1 test files
- `generate_v2_test_files.py` - Generates v2 test files
- `generate_v3_test_files.py` - Generates v3 test files

## Usage in Tests

### Vector Tests

The JSON test vectors are loaded and used in `tests/vector_tests.rs` to verify:
- Encryption produces expected ciphertext
- Decryption recovers original plaintext
- Round-trip encryption/decryption works correctly
- All versions (v0-v3) are properly supported

### File Operation Tests

The `.aes` files are used in `tests/file_ops_tests.rs` to test:
- Decryption of actual encrypted files
- File-based conversion operations
- Password rotation on real files
- Batch encryption/decryption with file I/O

## Notes

- The low iteration count (5) is intentional for fast test execution
- Production code should use higher iteration counts (e.g., 300,000+)
- All test files can be decrypted with password `"Hello"`
- The deterministic v3 files use fixed salts/IVs for reproducible encryption

