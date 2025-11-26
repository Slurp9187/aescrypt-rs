# AES Crypt Stream Format – Enhanced Specification  

This document is an **enhanced source** for the AES Crypt file format.

It is 100 % backward compatible with every file ever created by any official AES Crypt implementation (v0 through v3.x).

```text
               AES Crypt Stream Format
               Enhanced Specification

────────────────────────────────────────────────────────────────────────────
1. Common Header (all versions)
────────────────────────────────────────────────────────────────────────────
Offset  Size    Description
0       3       Magic bytes: "AES" (0x41 0x45 0x53)
3       1       Version
        0x00 → Version 0 (legacy, deprecated)
        0x01 → Version 1 (legacy, deprecated)
        0x02 → Version 2 (legacy, deprecated)
        0x03 → Version 3 (current and RECOMMENDED)
4       1       Reserved / special field
        • Version 0 : (ciphertext_length mod 16) in lower 4 bits
        • Version 1–3: MUST be 0x00

────────────────────────────────────────────────────────────────────────────
2. Extensions Block – Precise Location (Versions 2 and 3 only)
────────────────────────────────────────────────────────────────────────────
Begins **immediately at byte offset 5** (right after the reserved byte).

Repeats until a length field of 0x0000 is encountered.

Field              Size     Description
Length             u16 BE   Total length of this extension INCLUDING the length field itself
Identifier         1–127    UTF-8 string, null-terminated (0x00)
Data               N        Extension payload

Termination rule:
• A u16 length of exactly 0x0000 terminates the extensions block.
• The very next byte after this terminator is the first byte of the version-specific payload.

Special container extension (RECOMMENDED):
• Include one 128-byte extension with identifier = single 0x00 byte.
• This is the official "container" for future metadata without rewriting the file.

Extensions are neither encrypted nor authenticated — treat as untrusted metadata.

────────────────────────────────────────────────────────────────────────────
3. Version-Specific Layouts
────────────────────────────────────────────────────────────────────────────

┌──────────────────────────────────────────────────────────────────────┐
│                         VERSION 3 (0x03) – CURRENT                   │
└──────────────────────────────────────────────────────────────────────┘
After extensions terminator (or at offset 5 if terminator is immediate):

Offset  Size   Description
+0      4      KDF iterations (big-endian u32) → 1 ≤ iterations ≤ 5 000 000
+4      16     Public IV (random, used as PBKDF2 salt)
+20     48     Encrypted session material (exactly 3 full AES blocks)
               • Bytes 0–15  : Session IV
               • Bytes 16–47 : Session key (256-bit)
               Encryption: AES-256-CBC using
                   Key = PBKDF2-HMAC-SHA512(password_utf8, salt=Public_IV, iterations, dkLen=32)
                   IV  = Public_IV
                   Padding = none
+68     32     Session HMAC = HMAC-SHA256(encrypted_48_bytes || 0x03)
+100    N      Ciphertext (always multiple of 16 bytes, PKCS#7 padded)
+N      32     Final HMAC = HMAC-SHA256(ciphertext_bytes_only)

Minimum file size (empty plaintext): 132 + extensions bytes

KDF Details (v3) – Fully Specified
Password encoding : raw UTF-8 bytes (no null terminator)
Salt              : the 16-byte Public IV
PRF               : HMAC-SHA512
Iterations        : value from the 4-byte field
Output length     : exactly 32 bytes

Padding (v3)
PKCS#7 padding is mandatory.
pad_value = 16 − (plaintext_len mod 16)
Last pad_value bytes MUST equal pad_value.
Decryption MUST strictly validate all padding bytes.

┌──────────────────────────────────────────────────────────────────────┐
│                         VERSION 2 (0x02)                             │
└──────────────────────────────────────────────────────────────────────┘
After extensions terminator:
+0      16     Public IV
+16     48     Encrypted session IV + key (same layout, derived via legacy ACKDF)
+64     32     Session HMAC = HMAC-SHA256(encrypted_48_bytes)   ← no trailing byte
+N      N      Ciphertext (multiple of 16)
+N      1      Ciphertext length mod 16 (0–15)
+N+1    32     Final HMAC = HMAC-SHA256(ciphertext_bytes_only)

┌──────────────────────────────────────────────────────────────────────┐
│                         VERSION 1 (0x01)                             │
└──────────────────────────────────────────────────────────────────────┘
Identical layout and processing to Version 2.

┌──────────────────────────────────────────────────────────────────────┐
│                         VERSION 0 (0x00)                             │
└──────────────────────────────────────────────────────────────────────┘
Offset  Size   Description
0       3      "AES"
3       1      0x00
4       1      (ciphertext_length mod 16) in lower 4 bits
5       16     IV (used directly as CBC IV for bulk encryption)
21      N      Ciphertext
+N      32     Final HMAC = HMAC-SHA256(ciphertext_bytes_only)

Legacy ACKDF (used by v0–v2)
Password → UTF-16LE bytes (no BOM, no null terminator)
Repeatedly compute HMAC-SHA1(key=password_utf16le, message=salt || counter)
until 32 bytes are collected.

────────────────────────────────────────────────────────────────────────────
4. HMAC Coverage – CRITICAL
────────────────────────────────────────────────────────────────────────────
Session HMAC (v3)      → encrypted_session_block || 0x03
Session HMAC (v0–v2)   → encrypted_session_block only
Final trailer HMAC     → ciphertext octets ONLY
                         (never includes header, extensions, session block, or trailer)

────────────────────────────────────────────────────────────────────────────
5. Edge Cases & Mandatory Rules
────────────────────────────────────────────────────────────────────────────
• Empty plaintext is valid (ciphertext = one padded block → 16 bytes)
• KDF iterations = 0 or > 5 000 000 → reject file
• PKCS#7 padding validation is mandatory for v3
• Streaming implementations SHOULD verify session HMAC before processing ciphertext
• Maximum ciphertext length: 2⁶⁴ − 1 octets

────────────────────────────────────────────────────────────────────────────
6. Recommendations for New Files
────────────────────────────────────────────────────────────────────────────
• Always write version 3
• Use ≥ 300 000 iterations (default in aescrypt-rs)
• Include a 128-byte container extension
• Zeroize all key material and passwords in memory

────────────────────────────────────────────────────────────────────────────
7. Official Test Vectors
────────────────────────────────────────────────────────────────────────────
Permanently hosted and versioned at:
https://github.com/Slurp9187/aescrypt-rs/tree/main/tests/vector/data

These JSON files were extracted directly from Paul E. Jones’ official binary test suite
at https://github.com/terrapane/aescrypt_engine/tree/master/test

────────────────────────────────────────────────────────────────────────────
End of Specification
────────────────────────────────────────────────────────────────────────────