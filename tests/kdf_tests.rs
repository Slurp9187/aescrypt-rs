//! tests/kdf_tests.rs
//! General secure KDF tests — with merged edge cases, corrected PBKDF2 (2025)

mod common;

mod tests {
    use super::common::TEST_ITERATION_VALUES;

    use aescrypt_rs::aliases::{Aes256Key32, PasswordString, Salt16};
    use aescrypt_rs::{derive_ackdf_key, derive_pbkdf2_key};
    use secure_gate::RevealSecret;

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
        derive_ackdf_key(&password, &salt, &mut ackdf_key).unwrap();

        let expected_ackdf = [
            0x2d, 0xbb, 0x65, 0x84, 0x99, 0x12, 0x37, 0x80, 0x42, 0xb5, 0x11, 0x97, 0xae, 0xd9,
            0xc2, 0x79, 0x28, 0xf3, 0x07, 0x1f, 0xed, 0x7e, 0xb2, 0xe7, 0xe6, 0xaf, 0x5c, 0x6f,
            0x48, 0xde, 0x11, 0xeb,
        ];
        ackdf_key.with_secret(|ak| assert_eq!(ak, &expected_ackdf, "ACKDF mismatch"));

        let mut pbkdf2_key = Aes256Key32::new([0u8; 32]);
        derive_pbkdf2_key(&password, &salt, 1, &mut pbkdf2_key).unwrap();

        let expected_pbkdf2 = [
            142, 124, 235, 125, 184, 202, 68, 61, 255, 97, 150, 244, 189, 12, 170, 47, 125, 231,
            198, 156, 219, 100, 132, 2, 12, 34, 200, 165, 120, 169, 161, 207,
        ];
        pbkdf2_key.with_secret(|pk| assert_eq!(pk, &expected_pbkdf2, "PBKDF2 mismatch"));
    }

    #[test]
    fn secure_ackdf_and_pbkdf2_differ() {
        let password = PasswordString::new("correct horse battery staple".to_string());
        let salt = Salt16::from([0x11; 16]);

        let mut ackdf_key = Aes256Key32::new([0u8; 32]);
        derive_ackdf_key(&password, &salt, &mut ackdf_key).unwrap();

        let mut pbkdf2_key = Aes256Key32::new([0u8; 32]);
        derive_pbkdf2_key(&password, &salt, 1, &mut pbkdf2_key).unwrap();

        ackdf_key.with_secret(|ak| pbkdf2_key.with_secret(|pk| assert_ne!(ak, pk)));
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
                    KdfType::Ackdf => derive_ackdf_key(&password, &salt, &mut key).unwrap(),
                    KdfType::Pbkdf2 => derive_pbkdf2_key(&password, &salt, 1, &mut key).unwrap(),
                };
                key.with_secret(|k| assert_eq!(k.len(), 32, "{kdf:?} {desc} failed"));
            }
        }
    }

    #[test]
    fn pbkdf2_zero_iterations_clamps_to_one() {
        // Both `derive_pbkdf2_key` and `Pbkdf2Builder::with_iterations` clamp 0 → 1
        // so they are consistent. A 0-iteration call should succeed and produce the
        // same key as an explicit 1-iteration call.
        let password = PasswordString::new("test".to_string());
        let salt = Salt16::from([0x11; 16]);

        let mut key_zero = Aes256Key32::new([0u8; 32]);
        derive_pbkdf2_key(&password, &salt, 0, &mut key_zero).expect("0 should clamp to 1");

        let mut key_one = Aes256Key32::new([0u8; 32]);
        derive_pbkdf2_key(&password, &salt, 1, &mut key_one).expect("1 iteration should succeed");

        key_zero.with_secret(|kz| key_one.with_secret(|ko| assert_eq!(kz, ko)));
    }

    #[test]
    fn pbkdf2_various_iteration_counts() {
        let password = PasswordString::new("testpassword".to_string());
        let salt = Salt16::from([0x42; 16]);

        // Test with low iteration counts - performance testing is in benches/
        let iteration_counts = TEST_ITERATION_VALUES.to_vec();

        for &iterations in &iteration_counts {
            let mut key1 = Aes256Key32::new([0u8; 32]);
            let mut key2 = Aes256Key32::new([0u8; 32]);

            derive_pbkdf2_key(&password, &salt, iterations, &mut key1).unwrap();
            derive_pbkdf2_key(&password, &salt, iterations, &mut key2).unwrap();

            // Determinism: same input should produce same output
            key1.with_secret(|k1| {
                key2.with_secret(|k2| {
                    assert_eq!(
                        k1, k2,
                        "PBKDF2 should be deterministic with {iterations} iterations"
                    )
                })
            });

            // Verify output is 32 bytes
            assert_eq!(
                key1.with_secret(|k| k.len()),
                32,
                "PBKDF2 output should be 32 bytes with {iterations} iterations"
            );
        }
    }

    #[test]
    fn pbkdf2_different_iterations_produce_different_keys() {
        let password = PasswordString::new("testpassword".to_string());
        let salt = Salt16::from([0x42; 16]);

        let mut key1 = Aes256Key32::new([0u8; 32]);
        let mut key2 = Aes256Key32::new([0u8; 32]);
        let mut key3 = Aes256Key32::new([0u8; 32]);

        derive_pbkdf2_key(&password, &salt, 1, &mut key1).unwrap();
        derive_pbkdf2_key(&password, &salt, 10, &mut key2).unwrap();
        derive_pbkdf2_key(&password, &salt, 100, &mut key3).unwrap();

        // Different iteration counts should produce different keys
        key1.with_secret(|k1| {
            key2.with_secret(|k2| {
                assert_ne!(
                    k1, k2,
                    "Different iteration counts should produce different keys"
                )
            })
        });
        key2.with_secret(|k2| {
            key3.with_secret(|k3| {
                assert_ne!(
                    k2, k3,
                    "Different iteration counts should produce different keys"
                )
            })
        });
        key1.with_secret(|k1| {
            key3.with_secret(|k3| {
                assert_ne!(
                    k1, k3,
                    "Different iteration counts should produce different keys"
                )
            })
        });
    }

    #[test]
    fn kdf_determinism() {
        let password = PasswordString::new("deterministic test".to_string());
        let salt = Salt16::from([0xAA; 16]);

        // Test ACKDF determinism
        let mut ackdf_key1 = Aes256Key32::new([0u8; 32]);
        let mut ackdf_key2 = Aes256Key32::new([0u8; 32]);
        let mut ackdf_key3 = Aes256Key32::new([0u8; 32]);

        derive_ackdf_key(&password, &salt, &mut ackdf_key1).unwrap();
        derive_ackdf_key(&password, &salt, &mut ackdf_key2).unwrap();
        derive_ackdf_key(&password, &salt, &mut ackdf_key3).unwrap();

        ackdf_key1.with_secret(|k1| {
            ackdf_key2.with_secret(|k2| assert_eq!(k1, k2, "ACKDF should be deterministic"))
        });
        ackdf_key2.with_secret(|k2| {
            ackdf_key3.with_secret(|k3| assert_eq!(k2, k3, "ACKDF should be deterministic"))
        });

        // Test PBKDF2 determinism
        let mut pbkdf2_key1 = Aes256Key32::new([0u8; 32]);
        let mut pbkdf2_key2 = Aes256Key32::new([0u8; 32]);
        let mut pbkdf2_key3 = Aes256Key32::new([0u8; 32]);

        derive_pbkdf2_key(&password, &salt, 100, &mut pbkdf2_key1).unwrap();
        derive_pbkdf2_key(&password, &salt, 100, &mut pbkdf2_key2).unwrap();
        derive_pbkdf2_key(&password, &salt, 100, &mut pbkdf2_key3).unwrap();

        pbkdf2_key1.with_secret(|k1| {
            pbkdf2_key2.with_secret(|k2| assert_eq!(k1, k2, "PBKDF2 should be deterministic"))
        });
        pbkdf2_key2.with_secret(|k2| {
            pbkdf2_key3.with_secret(|k3| assert_eq!(k2, k3, "PBKDF2 should be deterministic"))
        });
    }

    #[test]
    fn kdf_salt_sensitivity() {
        let password = PasswordString::new("salt sensitivity test".to_string());

        let salt1 = Salt16::from([0x00; 16]);
        let salt2 = Salt16::from([0xFF; 16]);
        let salt3 = Salt16::from([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ]);

        // Test ACKDF salt sensitivity
        let mut ackdf_key1 = Aes256Key32::new([0u8; 32]);
        let mut ackdf_key2 = Aes256Key32::new([0u8; 32]);
        let mut ackdf_key3 = Aes256Key32::new([0u8; 32]);

        derive_ackdf_key(&password, &salt1, &mut ackdf_key1).unwrap();
        derive_ackdf_key(&password, &salt2, &mut ackdf_key2).unwrap();
        derive_ackdf_key(&password, &salt3, &mut ackdf_key3).unwrap();

        ackdf_key1.with_secret(|k1| {
            ackdf_key2.with_secret(|k2| {
                assert_ne!(
                    k1, k2,
                    "ACKDF should produce different keys for different salts"
                )
            })
        });
        ackdf_key2.with_secret(|k2| {
            ackdf_key3.with_secret(|k3| {
                assert_ne!(
                    k2, k3,
                    "ACKDF should produce different keys for different salts"
                )
            })
        });
        ackdf_key1.with_secret(|k1| {
            ackdf_key3.with_secret(|k3| {
                assert_ne!(
                    k1, k3,
                    "ACKDF should produce different keys for different salts"
                )
            })
        });

        // Test PBKDF2 salt sensitivity
        let mut pbkdf2_key1 = Aes256Key32::new([0u8; 32]);
        let mut pbkdf2_key2 = Aes256Key32::new([0u8; 32]);
        let mut pbkdf2_key3 = Aes256Key32::new([0u8; 32]);

        derive_pbkdf2_key(&password, &salt1, 100, &mut pbkdf2_key1).unwrap();
        derive_pbkdf2_key(&password, &salt2, 100, &mut pbkdf2_key2).unwrap();
        derive_pbkdf2_key(&password, &salt3, 100, &mut pbkdf2_key3).unwrap();

        pbkdf2_key1.with_secret(|k1| {
            pbkdf2_key2.with_secret(|k2| {
                assert_ne!(
                    k1, k2,
                    "PBKDF2 should produce different keys for different salts"
                )
            })
        });
        pbkdf2_key2.with_secret(|k2| {
            pbkdf2_key3.with_secret(|k3| {
                assert_ne!(
                    k2, k3,
                    "PBKDF2 should produce different keys for different salts"
                )
            })
        });
        pbkdf2_key1.with_secret(|k1| {
            pbkdf2_key3.with_secret(|k3| {
                assert_ne!(
                    k1, k3,
                    "PBKDF2 should produce different keys for different salts"
                )
            })
        });
    }

    #[test]
    fn kdf_password_sensitivity() {
        let salt = Salt16::from([0x42; 16]);

        let password1 = PasswordString::new("password1".to_string());
        let password2 = PasswordString::new("password2".to_string());
        let password3 = PasswordString::new("different password entirely".to_string());

        // Test ACKDF password sensitivity
        let mut ackdf_key1 = Aes256Key32::new([0u8; 32]);
        let mut ackdf_key2 = Aes256Key32::new([0u8; 32]);
        let mut ackdf_key3 = Aes256Key32::new([0u8; 32]);

        derive_ackdf_key(&password1, &salt, &mut ackdf_key1).unwrap();
        derive_ackdf_key(&password2, &salt, &mut ackdf_key2).unwrap();
        derive_ackdf_key(&password3, &salt, &mut ackdf_key3).unwrap();

        ackdf_key1.with_secret(|k1| {
            ackdf_key2.with_secret(|k2| {
                assert_ne!(
                    k1, k2,
                    "ACKDF should produce different keys for different passwords"
                )
            })
        });
        ackdf_key2.with_secret(|k2| {
            ackdf_key3.with_secret(|k3| {
                assert_ne!(
                    k2, k3,
                    "ACKDF should produce different keys for different passwords"
                )
            })
        });
        ackdf_key1.with_secret(|k1| {
            ackdf_key3.with_secret(|k3| {
                assert_ne!(
                    k1, k3,
                    "ACKDF should produce different keys for different passwords"
                )
            })
        });

        // Test PBKDF2 password sensitivity
        let mut pbkdf2_key1 = Aes256Key32::new([0u8; 32]);
        let mut pbkdf2_key2 = Aes256Key32::new([0u8; 32]);
        let mut pbkdf2_key3 = Aes256Key32::new([0u8; 32]);

        derive_pbkdf2_key(&password1, &salt, 100, &mut pbkdf2_key1).unwrap();
        derive_pbkdf2_key(&password2, &salt, 100, &mut pbkdf2_key2).unwrap();
        derive_pbkdf2_key(&password3, &salt, 100, &mut pbkdf2_key3).unwrap();

        pbkdf2_key1.with_secret(|k1| {
            pbkdf2_key2.with_secret(|k2| {
                assert_ne!(
                    k1, k2,
                    "PBKDF2 should produce different keys for different passwords"
                )
            })
        });
        pbkdf2_key2.with_secret(|k2| {
            pbkdf2_key3.with_secret(|k3| {
                assert_ne!(
                    k2, k3,
                    "PBKDF2 should produce different keys for different passwords"
                )
            })
        });
        pbkdf2_key1.with_secret(|k1| {
            pbkdf2_key3.with_secret(|k3| {
                assert_ne!(
                    k1, k3,
                    "PBKDF2 should produce different keys for different passwords"
                )
            })
        });
    }

    #[test]
    fn kdf_output_buffer_validation() {
        let password = PasswordString::new("buffer test".to_string());
        let salt = Salt16::from([0x33; 16]);

        // Test ACKDF output buffer
        let mut ackdf_key = Aes256Key32::new([0u8; 32]);
        derive_ackdf_key(&password, &salt, &mut ackdf_key).unwrap();

        assert_eq!(
            ackdf_key.with_secret(|k| k.len()),
            32,
            "ACKDF output should be exactly 32 bytes"
        );
        // Verify buffer is not all zeros (very unlikely but good to check)
        assert!(
            ackdf_key.with_secret(|k| k.iter().any(|&b| b != 0)),
            "ACKDF output should not be all zeros"
        );

        // Test PBKDF2 output buffer
        let mut pbkdf2_key = Aes256Key32::new([0u8; 32]);
        derive_pbkdf2_key(&password, &salt, 100, &mut pbkdf2_key).unwrap();

        assert_eq!(
            pbkdf2_key.with_secret(|k| k.len()),
            32,
            "PBKDF2 output should be exactly 32 bytes"
        );
        // Verify buffer is not all zeros
        assert!(
            pbkdf2_key.with_secret(|k| k.iter().any(|&b| b != 0)),
            "PBKDF2 output should not be all zeros"
        );
    }
}
