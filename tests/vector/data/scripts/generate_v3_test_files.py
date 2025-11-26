#!/usr/bin/env python3
"""
Generate binary .aes test files from JSON test vectors.

Input:  tests/data/test_vectors_v3.json
Output: tests/data/aes/v3/v3_test_{i}.txt.aes
"""

import json
import binascii
from pathlib import Path

# Configuration
VERSION = "v3"
INPUT_DIR = Path("tests/vector/data")
INPUT_FILE = INPUT_DIR / f"test_vectors_{VERSION}.json"
OUTPUT_DIR = INPUT_DIR / "aes_test_files" / VERSION

# Ensure output directory exists
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Load and process test vectors
with INPUT_FILE.open("r", encoding="utf-8") as f:
    vectors = json.load(f)

for idx, vec in enumerate(vectors):
    ciphertext_hex = vec["ciphertext_hex"]
    binary_data = binascii.unhexlify(ciphertext_hex)
    filename = f"{VERSION}_test_{idx}.txt.aes"
    output_path = OUTPUT_DIR / filename

    with output_path.open("wb") as f:
        f.write(binary_data)

    print(f"Generated {output_path.name} ({len(binary_data)} bytes)")
