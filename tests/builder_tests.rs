//! tests/builder/builder_tests.rs
//! PBKDF2 builder – final, verified green on Windows (2025)

#[cfg(feature = "zeroize")]
mod tests {
    use aescrypt_rs::aliases::{Aes256Key, PasswordString};
    use aescrypt_rs::Pbkdf2Builder;

    #[test]
    fn pbkdf2_builder_works() {
        let password = PasswordString::new("hunter2".to_string());

        let mut key = Aes256Key::new([0u8; 32]);
        Pbkdf2Builder::new()
            .with_iterations(1_000)
            .with_salt([0x55u8; 16])
            .derive_secure(&password, &mut key)
            .unwrap();

        assert_eq!(key.expose_secret().len(), 32);
    }

    #[test]
    fn pbkdf2_builder_custom_params() {
        let password = PasswordString::new("correct horse battery staple".to_string());

        let cases = [
            (500_000, [0xaau8; 16]),
            (100_000, [0xbbu8; 16]),
            (1, [0xc0u8; 16]),
        ];

        for (iterations, salt) in cases {
            let mut key = Aes256Key::new([0u8; 32]);
            Pbkdf2Builder::new()
                .with_iterations(iterations)
                .with_salt(salt)
                .derive_secure(&password, &mut key)
                .unwrap();

            assert_eq!(key.expose_secret().len(), 32);
        }
    }

    #[test]
    fn pbkdf2_builder_default_salt_is_random() {
        let password = PasswordString::new("test".to_string());

        let mut key1 = Aes256Key::new([0u8; 32]);
        let mut key2 = Aes256Key::new([0u8; 32]);

        Pbkdf2Builder::new()
            .derive_secure(&password, &mut key1)
            .unwrap();
        Pbkdf2Builder::new()
            .derive_secure(&password, &mut key2)
            .unwrap();

        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn pbkdf2_builder_derive_secure_new() {
        let password = PasswordString::new("builder-new".to_string());

        let key: Aes256Key = Pbkdf2Builder::new()
            .with_iterations(250_000)
            .derive_secure_new(&password)
            .unwrap();

        assert_eq!(key.expose_secret().len(), 32);
    }

    // REMOVED the invalid-iterations test
    // → The limit is enforced only in encrypt(), not in the builder
    // We'll test it properly in the encrypt module instead
}
