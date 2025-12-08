#!/usr/bin/env python3
"""
Generate .aes test files from JSON test vectors for all AES Crypt versions.

This script generates binary .aes test files from JSON test vectors for:
- v0, v1, v2, v3 (from test_vectors_v*.json)
- Deterministic v3 (from deterministic_test_vectors_v3.json)

Works correctly on Windows 11 from ANY directory.
"""

import json
import binascii
from pathlib import Path
from datetime import datetime

# ----------------------------------------------------------------------
# 1. Find the REAL project root (the folder that contains Cargo.toml)
# ----------------------------------------------------------------------


def find_project_root() -> Path:
    start = Path(__file__).resolve()
    for candidate in [start] + list(start.parents):
        # Stop at drive root
        if candidate == candidate.parent:
            break
        # We found the repo if Cargo.toml exists AND the folder name is aescrypt-rs
        cargo_toml = candidate / "Cargo.toml"
        if cargo_toml.is_file():
            # Extra safety – make sure it's our repo
            if candidate.name == "aescrypt-rs" or (candidate / "src").exists():
                return candidate
    raise RuntimeError(
        "Could not locate project root! Make sure this script is inside the aescrypt-rs repository."
    )


PROJECT_ROOT = find_project_root()
DATA_DIR = PROJECT_ROOT / "tests" / "test_data"
OUTPUT_ROOT = DATA_DIR / "aes_test_files"

print(f"Project root detected : {PROJECT_ROOT}")
print(f"Vector data directory : {DATA_DIR}")
print(f"Output directory      : {OUTPUT_ROOT}")
print()

if not DATA_DIR.exists():
    raise RuntimeError(f"Test vector directory not found: {DATA_DIR}")

# ----------------------------------------------------------------------
# 2. Configuration
# ----------------------------------------------------------------------
VERSIONS = ["v0", "v1", "v2", "v3"]
DETERMINISTIC_FILE = DATA_DIR / "deterministic_test_vectors_v3.json"
INCLUDE_DETERMINISTIC = True

OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)


# ----------------------------------------------------------------------
# 3. Core generation functions
# ----------------------------------------------------------------------
def generate_for_version(version: str):
    input_file = DATA_DIR / f"test_vectors_{version}.json"
    if not input_file.is_file():
        print(
            f"Warning: Missing {input_file.name} — skipping {version.upper()}")
        return

    out_dir = OUTPUT_ROOT / version
    out_dir.mkdir(exist_ok=True)

    with input_file.open("r", encoding="utf-8") as f:
        vectors = json.load(f)

    print(f"Generating {version.upper()} → {len(vectors)} files")

    for i, vec in enumerate(vectors):
        hex_data = vec.get("ciphertext_hex") or vec.get("encrypted_hex")
        if not hex_data:
            print(f"  Warning: vector {i} has no ciphertext – skipped")
            continue

        try:
            binary = binascii.unhexlify(hex_data.strip())
        except binascii.Error as e:
            print(f"  Error: bad hex in vector {i}: {e}")
            continue

        filename = f"{version}_test_{i:02d}.txt.aes"
        path = out_dir / filename
        path.write_bytes(binary)
        print(f"  → {path.name} ({len(binary)} bytes)")

    print(f"Success: {version.upper()} complete\n")


def generate_deterministic():
    if not DETERMINISTIC_FILE.is_file():
        print("Warning: deterministic_test_vectors_v3.json not found – skipping")
        return

    out_dir = OUTPUT_ROOT / "v3"
    out_dir.mkdir(exist_ok=True)

    vectors = json.load(DETERMINISTIC_FILE.open("r", encoding="utf-8"))
    print(f"Generating deterministic v3 → {len(vectors)} files")

    for i, vec in enumerate(vectors):
        binary = binascii.unhexlify(vec["ciphertext_hex"].strip())
        filename = f"v3_deterministic_{i:02d}.txt.aes"
        path = out_dir / filename
        path.write_bytes(binary)
        print(f"  → {filename} ({len(binary)} bytes)")

    print("Success: Deterministic v3 complete\n")


# ----------------------------------------------------------------------
# 4. Run
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 80)
    print("AES Crypt .aes Test File Generator (v0–v3 + deterministic)")
    print(f"Started : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 80)

    for v in VERSIONS:
        generate_for_version(v)

    if INCLUDE_DETERMINISTIC:
        generate_deterministic()

    print("ALL DONE!")
    print("\nNext steps (PowerShell):")
    print('''    git add tests/test_data/aes_test_files
    git commit -m "Regenerate all v0-v3 + deterministic .aes test files"
    git push''')
