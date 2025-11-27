#[cfg(feature = "batch-ops")]
#[test]
fn batch_roundtrip_sanity_check() {
    use aescrypt_rs::aliases::Password;
    use aescrypt_rs::{decrypt_batch, encrypt_batch};
    use std::io::Cursor;

    let password = Password::new("sanity".to_string());
    let data = [b"hello parallel world"; 4]; // 4 tiny files

    let mut encrypted = data.map(|d| (Cursor::new(d.to_vec()), Vec::new()));
    encrypt_batch(&mut encrypted, &password, 1000).unwrap();

    let mut decrypted = encrypted
        .into_iter()
        .map(|(_, buf)| (Cursor::new(buf), Vec::new()))
        .collect::<Vec<_>>();
    decrypt_batch(&mut decrypted, &password).unwrap();

    let results: Vec<_> = decrypted.into_iter().map(|(_, buf)| buf).collect();
    assert_eq!(results, data.as_ref());
}
