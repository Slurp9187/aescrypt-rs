# Replace All Raw Arrays with Secure-Gate Types in Encryptor Module

## Overview
Ensure all sensitive data in the encryptor module uses secure-gate types instead of raw arrays for consistent memory safety, automatic zeroization, and better code clarity.

## Changes Required

### 1. `src/encryptor/encrypt.rs` - Use `.into()` for type conversion
- **Lines 48-50**: Replace redundant `Fixed::from(*...expose_secret())` with `.into()`
  - `RandomIv16::generate()` returns `RandomIv16` (which is `Fixed<[u8; 16]>`)
  - `RandomAes256Key32::generate()` returns `RandomAes256Key32` (which is `Fixed<[u8; 32]>`)
  - Both can be converted to `Iv16` and `Aes256Key32` respectively using `.into()` (provided by secure-gate's "conversions" feature)
  - Change: `let public_iv: Iv16 = RandomIv16::generate().into();`
  - Change: `let session_iv: Iv16 = RandomIv16::generate().into();`
  - Change: `let session_key: Aes256Key32 = RandomAes256Key32::generate().into();`
- **Line 18**: Remove unused `use secure_gate::Fixed;` import (no longer needed)

### 2. `src/encryptor/session.rs` - Replace raw array with Block16
- **Line 75**: Replace `let mut prev = *public_iv.expose_secret();` with `let mut prev_block = Block16::new(*public_iv.expose_secret());`
- **Line 79**: Update `xor_blocks` call to use `prev_block.expose_secret()` instead of `&prev`
- **Line 84**: Replace `prev.copy_from_slice(&enc_block.expose_secret()[0..16]);` with `prev_block = Block16::new(*enc_block.expose_secret()[0..16].try_into().expect("always 16 bytes"));`
- **Line 89**: Update `xor_blocks` call to use `prev_block.expose_secret()` instead of `&prev`
- **Line 96**: Replace `prev.copy_from_slice(&enc_block.expose_secret()[16..32]);` with `prev_block = Block16::new(*enc_block.expose_secret()[16..32].try_into().expect("always 16 bytes"));`
- **Line 101**: Update `xor_blocks` call to use `prev_block.expose_secret()` instead of `&prev`
- Add `use std::convert::TryInto;` if not already present

### 3. `src/encryptor/stream.rs` - Optimize unnecessary allocation
- **Lines 53-55**: Eliminate unnecessary `Block16` allocation
  - Current: Creates `ct_block` just to copy from `aes_block`, then immediately uses it
  - Change: Use `aes_block.as_ref()` directly for HMAC and write
  - Update `prev_block` assignment to create from slice: `prev_block = Block16::new(*ct_slice.try_into().expect("always 16 bytes"));`
- Add `use std::convert::TryInto;` if not already present

## Files to Modify
1. `src/encryptor/encrypt.rs` - Use `.into()` for conversions, remove unused import
2. `src/encryptor/session.rs` - Replace raw array with `Block16`, add `TryInto` import
3. `src/encryptor/stream.rs` - Optimize allocation, add `TryInto` import

## Verification
- All tests should pass (no logic changes, only type improvements)
- No compilation errors
- Secure-gate types used consistently throughout
- Automatic zeroization enabled for all sensitive buffers
- No unnecessary secret exposure via `.expose_secret()` for type conversions

