//! tests/kdf/kdf_tests.rs
//! General secure KDF tests — with merged edge cases, corrected PBKDF2 (2025)

#[cfg(feature = "zeroize")]
mod tests {
    use aescrypt_rs::aliases::{Aes256Key32, PasswordString, Salt16};
    use aescrypt_rs::{derive_secure_ackdf_key, derive_secure_pbkdf2_key};

    #[derive(Debug, Copy, Clone)]
    enum KdfType {
        Ackdf,
        Pbkdf2,
    }

    #[test]
    fn secure_kdf_expected_keys() {
        let password = PasswordString::new("correct horse battery staple".to_string());
        let salt = Salt16::from([0x11; 16]);

        let mut ackdf_key = Aes256Key32::new([0u8; 32]);
        derive_secure_ackdf_key(&password, &salt, &mut ackdf_key).unwrap();

        let expected_ackdf = [
            0x2d, 0xbb, 0x65, 0x84, 0x99, 0x12, 0x37, 0x80, 0x42, 0xb5, 0x11, 0x97, 0xae, 0xd9,
            0xc2, 0x79, 0x28, 0xf3, 0x07, 0x1f, 0xed, 0x7e, 0xb2, 0xe7, 0xe6, 0xaf, 0x5c, 0x6f,
            0x48, 0xde, 0x11, 0xeb,
        ];
        assert_eq!(ackdf_key.expose_secret(), &expected_ackdf, "ACKDF mismatch");

        let mut pbkdf2_key = Aes256Key32::new([0u8; 32]);
        derive_secure_pbkdf2_key(&password, &salt, 1, &mut pbkdf2_key).unwrap();

        let expected_pbkdf2 = [
            142, 124, 235, 125, 184, 202, 68, 61, 255, 97, 150, 244, 189, 12, 170, 47, 125, 231,
            198, 156, 219, 100, 132, 2, 12, 34, 200, 165, 120, 169, 161, 207,
        ];
        assert_eq!(
            pbkdf2_key.expose_secret(),
            &expected_pbkdf2,
            "PBKDF2 mismatch"
        );
    }

    #[test]
    fn secure_ackdf_and_pbkdf2_differ() {
        let password = PasswordString::new("correct horse battery staple".to_string());
        let salt = Salt16::from([0x11; 16]);

        let mut ackdf_key = Aes256Key32::new([0u8; 32]);
        derive_secure_ackdf_key(&password, &salt, &mut ackdf_key).unwrap();

        let mut pbkdf2_key = Aes256Key32::new([0u8; 32]);
        derive_secure_pbkdf2_key(&password, &salt, 1, &mut pbkdf2_key).unwrap();

        assert_ne!(ackdf_key.expose_secret(), pbkdf2_key.expose_secret());
    }

    #[test]
    fn secure_kdf_edge_cases() {
        // Bind large to variable
        let large_password = (0..1000).map(|_| "a").collect::<String>();

        let cases = vec![
            ("", "empty password"),
            ("パスワード123!@#", "unicode password"),
            (&large_password, "large password"),
        ];

        for (pw_str, desc) in cases {
            let password = PasswordString::new(pw_str.to_string());
            let salt = Salt16::from([0x42u8; 16]);

            for kdf in [KdfType::Ackdf, KdfType::Pbkdf2] {
                let mut key = Aes256Key32::new([0u8; 32]);
                match kdf {
                    KdfType::Ackdf => derive_secure_ackdf_key(&password, &salt, &mut key).unwrap(),
                    KdfType::Pbkdf2 => {
                        derive_secure_pbkdf2_key(&password, &salt, 1, &mut key).unwrap()
                    }
                };
                assert_eq!(key.expose_secret().len(), 32, "{kdf:?} {desc} failed");
            }
        }
    }
}
