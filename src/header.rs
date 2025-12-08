
use crate::error::AescryptError;
use std::io::Read;

pub fn read_version<R: Read>(mut reader: R) -> Result<u8, AescryptError> {
    let mut magic = [0u8; 3];
    reader.read_exact(&mut magic).map_err(AescryptError::Io)?;

    if magic != [b'A', b'E', b'S'] {
        return Err(AescryptError::Header(
            "Not an AES Crypt file: invalid magic".into(),
        ));
    }

    let mut buf = [0u8; 2];
    match reader.read(&mut buf) {
        Ok(2) => {
            let version = buf[0];
            let reserved = buf[1];

            if version > 3 {
                return Err(AescryptError::Header(format!(
                    "Unsupported version: {version}"
                )));
            }
            if version >= 1 && reserved != 0x00 {
                return Err(AescryptError::Header(
                    "Invalid header: reserved byte != 0x00".into(),
                ));
            }
            Ok(version)
        }
        Ok(1) => {
            // Only one byte after "AES" → legacy v0 4-byte header
            if buf[0] == 0 {
                Ok(0)
            } else {
                Err(AescryptError::Header(
                    "Invalid v0 header: version byte not zero".into(),
                ))
            }
        }
        Ok(0) | Err(_) => {
            // EOF after "AES" → classic 3-byte v0 header
            Ok(0)
        }
        _ => unreachable!("read() only returns 0–2 for a 2-byte buffer"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn real_world_vectors() {
        let cases = &[
            ("41455300", 0u8),   // v0: 4-byte
            ("4145530000", 0u8), // v0: 5-byte clean
            ("41455300ff", 0u8), // v0: 5-byte garbage
            ("4145530100", 1u8),
            ("4145530200", 2u8),
            ("4145530300", 3u8),
        ];

        for &(hex, expected) in cases {
            let bytes = hex::decode(hex).unwrap();
            assert_eq!(read_version(Cursor::new(&bytes)).unwrap(), expected);
        }
    }

    #[test]
    fn short_file_only_aes() {
        assert_eq!(read_version(Cursor::new(b"AES")).unwrap(), 0);
    }

    #[test]
    fn invalid_magic() {
        let err = read_version(Cursor::new(b"XYZ\x03\x00")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Header error: Not an AES Crypt file: invalid magic"
        );
    }
}
