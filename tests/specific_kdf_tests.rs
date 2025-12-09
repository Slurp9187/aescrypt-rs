//! tests/specific_kdf_tests.rs
//! Merged ACKDF/PBKDF2 vector tests — correct expected values (2025)

#[cfg(feature = "zeroize")]
mod tests {
    use aescrypt_rs::aliases::{Aes256Key32, PasswordString, Salt16};
    use aescrypt_rs::{derive_ackdf_key, derive_pbkdf2_key};

    #[derive(Debug, Copy, Clone)]
    enum KdfType {
        Ackdf,
        Pbkdf2,
    }

    #[test]
    fn zero_salt_real_vector() {
        let cases = vec![
            (
                KdfType::Ackdf,
                [
                    0x08, 0x29, 0x80, 0x2e, 0x78, 0xe7, 0x94, 0x89, 0x57, 0x75, 0xb3, 0x3d, 0x57,
                    0x66, 0x6d, 0x8a, 0xb9, 0x3c, 0x24, 0xb3, 0x66, 0x75, 0x9e, 0xa4, 0xe3, 0x4f,
                    0x8f, 0xa1, 0x05, 0x51, 0x42, 0x9d,
                ],
            ),
            (
                KdfType::Pbkdf2,
                [
                    167, 57, 76, 179, 177, 79, 158, 109, 43, 160, 214, 98, 27, 37, 252, 96, 55, 5,
                    173, 156, 134, 154, 132, 213, 191, 42, 139, 58, 99, 106, 16, 30,
                ],
            ),
        ];

        for (kdf, expected) in cases {
            let password = PasswordString::new("testpassword".to_owned());
            let salt = Salt16::from([0u8; 16]);

            let mut key = Aes256Key32::new([0u8; 32]);
            match kdf {
                KdfType::Ackdf => derive_ackdf_key(&password, &salt, &mut key).unwrap(),
                KdfType::Pbkdf2 => derive_pbkdf2_key(&password, &salt, 1, &mut key).unwrap(),
            };

            assert_eq!(key.expose_secret(), &expected, "{kdf:?} zero salt mismatch");
        }
    }

    #[test]
    fn custom_salt_real_vector() {
        let cases = vec![
            (
                KdfType::Ackdf,
                [
                    0xc8, 0x54, 0xf4, 0x22, 0xed, 0x41, 0xe8, 0x2f, 0xe3, 0x51, 0x6e, 0x7c, 0xc8,
                    0x2a, 0x18, 0x92, 0x38, 0xa4, 0x73, 0xf0, 0xd2, 0x1d, 0x89, 0xcb, 0xe6, 0x01,
                    0x5a, 0x61, 0x6d, 0xa9, 0xc8, 0x14,
                ],
            ),
            (
                KdfType::Pbkdf2,
                [
                    4, 191, 140, 108, 114, 167, 241, 252, 198, 2, 56, 122, 61, 238, 138, 11, 206,
                    58, 201, 194, 147, 78, 174, 111, 9, 86, 185, 7, 89, 154, 85, 55,
                ],
            ),
        ];

        for (kdf, expected) in cases {
            let password = PasswordString::new("password".to_owned());
            let salt = Salt16::from([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]);

            let mut key = Aes256Key32::new([0u8; 32]);
            match kdf {
                KdfType::Ackdf => derive_ackdf_key(&password, &salt, &mut key).unwrap(),
                KdfType::Pbkdf2 => derive_pbkdf2_key(&password, &salt, 1, &mut key).unwrap(),
            };

            assert_eq!(
                key.expose_secret(),
                &expected,
                "{kdf:?} custom salt mismatch"
            );
        }
    }
}

