//! tests/builder/builder_tests.rs
//! PBKDF2 builder – final, verified green on Windows (2025)

mod common;

#[cfg(feature = "zeroize")]
mod tests {
    use super::common::TEST_ITERATIONS;

    use aescrypt_rs::aliases::{Aes256Key32, PasswordString};
    use aescrypt_rs::Pbkdf2Builder;
    use secure_gate::ExposeSecret;

    #[test]
    fn pbkdf2_builder_works() {
        let password = PasswordString::new("hunter2".to_string());

        let mut key = Aes256Key32::new([0u8; 32]);
        Pbkdf2Builder::new()
            .with_iterations(1_000)
            .with_salt([0x55u8; 16])
            .derive_secure(&password, &mut key)
            .unwrap();

        key.with_secret(|k| assert_eq!(k.len(), 32));
    }

    #[test]
    fn pbkdf2_builder_custom_params() {
        let password = PasswordString::new("correct horse battery staple".to_string());

        // Test with low iteration counts - performance testing is in benches/
        let cases = [
            (TEST_ITERATIONS, [0xaau8; 16]),
            (TEST_ITERATIONS, [0xbbu8; 16]),
            (1, [0xc0u8; 16]),
        ];

        for (iterations, salt) in cases {
            let mut key = Aes256Key32::new([0u8; 32]);
            Pbkdf2Builder::new()
                .with_iterations(iterations)
                .with_salt(salt)
                .derive_secure(&password, &mut key)
                .unwrap();

            key.with_secret(|k| assert_eq!(k.len(), 32));
        }
    }

    #[test]
    #[cfg(feature = "rand")]
    fn pbkdf2_builder_default_salt_is_random() {
        let password = PasswordString::new("test".to_string());

        let mut key1 = Aes256Key32::new([0u8; 32]);
        let mut key2 = Aes256Key32::new([0u8; 32]);

        Pbkdf2Builder::new()
            .derive_secure(&password, &mut key1)
            .unwrap();
        Pbkdf2Builder::new()
            .derive_secure(&password, &mut key2)
            .unwrap();

        assert!(key1.with_secret(|k1| key2.with_secret(|k2| k1 != k2)));
    }

    #[test]
    fn pbkdf2_builder_derive_secure_new() {
        let password = PasswordString::new("builder-new".to_string());

        let key: Aes256Key32 = Pbkdf2Builder::new()
            .with_iterations(250_000)
            .derive_secure_new(&password)
            .unwrap();

        key.with_secret(|k| assert_eq!(k.len(), 32));
    }

    // REMOVED the invalid-iterations test
    // → The limit is enforced only in encrypt(), not in the builder
    // We'll test it properly in the encrypt module instead

    #[test]
    fn pbkdf2_builder_default_trait() {
        let password = PasswordString::new("default-test".to_string());
        let mut key = Aes256Key32::new([0u8; 32]);

        Pbkdf2Builder::default()
            .derive_secure(&password, &mut key)
            .unwrap();

        key.with_secret(|k| assert_eq!(k.len(), 32));
    }

    #[test]
    fn pbkdf2_builder_iterations_clamps_to_one() {
        let builder = Pbkdf2Builder::new().with_iterations(0);
        assert_eq!(builder.iterations(), 1, "Iterations should clamp to 1");
    }

    #[test]
    fn pbkdf2_builder_determinism() {
        let password = PasswordString::new("deterministic".to_string());
        let salt = [0xCC; 16];
        let iterations = TEST_ITERATIONS;

        let mut key1 = Aes256Key32::new([0u8; 32]);
        let mut key2 = Aes256Key32::new([0u8; 32]);

        Pbkdf2Builder::new()
            .with_iterations(iterations)
            .with_salt(salt)
            .derive_secure(&password, &mut key1)
            .unwrap();

        Pbkdf2Builder::new()
            .with_iterations(iterations)
            .with_salt(salt)
            .derive_secure(&password, &mut key2)
            .unwrap();

        key1.with_secret(|k1| {
            key2.with_secret(|k2| {
                assert_eq!(
                    k1, k2,
                    "PBKDF2 should be deterministic with {iterations} iterations"
                )
            })
        });
    }

    #[test]
    fn pbkdf2_builder_salt_sensitivity() {
        let password = PasswordString::new("salt-test".to_string());
        let iterations = TEST_ITERATIONS;

        let mut key1 = Aes256Key32::new([0u8; 32]);
        let mut key2 = Aes256Key32::new([0u8; 32]);

        Pbkdf2Builder::new()
            .with_iterations(iterations)
            .with_salt([0x11; 16])
            .derive_secure(&password, &mut key1)
            .unwrap();

        Pbkdf2Builder::new()
            .with_iterations(iterations)
            .with_salt([0x22; 16])
            .derive_secure(&password, &mut key2)
            .unwrap();

        key1.with_secret(|k1| {
            key2.with_secret(|k2| {
                assert_ne!(k1, k2, "Different salts should produce different keys")
            })
        });
    }

    #[test]
    fn pbkdf2_builder_iteration_sensitivity() {
        let password = PasswordString::new("iteration-test".to_string());
        let salt = [0xDD; 16];

        let mut key1 = Aes256Key32::new([0u8; 32]);
        let mut key2 = Aes256Key32::new([0u8; 32]);

        Pbkdf2Builder::new()
            .with_iterations(1_000)
            .with_salt(salt)
            .derive_secure(&password, &mut key1)
            .unwrap();

        Pbkdf2Builder::new()
            .with_iterations(2_000)
            .with_salt(salt)
            .derive_secure(&password, &mut key2)
            .unwrap();

        key1.with_secret(|k1| {
            key2.with_secret(|k2| {
                assert_ne!(k1, k2, "Different iterations should produce different keys")
            })
        });
    }

    #[test]
    fn pbkdf2_builder_password_sensitivity() {
        let salt = [0xEE; 16];
        let iterations = TEST_ITERATIONS;

        let mut key1 = Aes256Key32::new([0u8; 32]);
        let mut key2 = Aes256Key32::new([0u8; 32]);

        Pbkdf2Builder::new()
            .with_iterations(iterations)
            .with_salt(salt)
            .derive_secure(&PasswordString::new("password1".to_string()), &mut key1)
            .unwrap();

        Pbkdf2Builder::new()
            .with_iterations(iterations)
            .with_salt(salt)
            .derive_secure(&PasswordString::new("password2".to_string()), &mut key2)
            .unwrap();

        key1.with_secret(|k1| {
            key2.with_secret(|k2| {
                assert_ne!(k1, k2, "Different passwords should produce different keys")
            })
        });
    }

    #[test]
    fn pbkdf2_builder_chaining() {
        let password = PasswordString::new("chaining-test".to_string());
        let mut key = Aes256Key32::new([0u8; 32]);

        let builder = Pbkdf2Builder::new()
            .with_iterations(5_000)
            .with_salt([0xFF; 16])
            .with_iterations(TEST_ITERATIONS) // Override previous
            .with_salt([0xAA; 16]); // Override previous

        assert_eq!(builder.iterations(), TEST_ITERATIONS);

        builder.derive_secure(&password, &mut key).unwrap();
        key.with_secret(|k| assert_eq!(k.len(), 32));
    }

    #[test]
    fn pbkdf2_builder_default_iterations() {
        use aescrypt_rs::constants::DEFAULT_PBKDF2_ITERATIONS;

        let builder = Pbkdf2Builder::new();
        assert_eq!(
            builder.iterations(),
            DEFAULT_PBKDF2_ITERATIONS,
            "Default iterations should match DEFAULT_PBKDF2_ITERATIONS"
        );
    }

    #[test]
    fn pbkdf2_builder_unicode_password() {
        let password = PasswordString::new("パスワード123!@#".to_string());
        let mut key = Aes256Key32::new([0u8; 32]);

        Pbkdf2Builder::new()
            .with_iterations(1_000)
            .with_salt([0x99; 16])
            .derive_secure(&password, &mut key)
            .unwrap();

        key.with_secret(|k| assert_eq!(k.len(), 32));
    }

    #[test]
    fn pbkdf2_builder_empty_password() {
        let password = PasswordString::new(String::new());
        let mut key = Aes256Key32::new([0u8; 32]);

        // Empty password should still work (though not recommended)
        let result = Pbkdf2Builder::new()
            .with_iterations(1_000)
            .with_salt([0x88; 16])
            .derive_secure(&password, &mut key);

        // PBKDF2 should accept empty password (though it's not secure)
        assert!(result.is_ok());
        key.with_secret(|k| assert_eq!(k.len(), 32));
    }
}
