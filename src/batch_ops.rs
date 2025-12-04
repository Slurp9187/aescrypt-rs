#[cfg(feature = "batch-ops")]
use rayon::prelude::*;
#[cfg(feature = "batch-ops")]
use std::io::{Read, Write};

#[cfg(feature = "batch-ops")]
use crate::aliases::PasswordString;
#[cfg(feature = "batch-ops")]
use crate::{decrypt, encrypt, AescryptError};

#[cfg(feature = "batch-ops")]
pub fn encrypt_batch<R, W>(
    batch: &mut [(R, W)],
    password: &PasswordString,
    iterations: u32,
) -> Result<(), AescryptError>
where
    R: Read + Send,
    W: Write + Send,
{
    batch
        .par_iter_mut()
        .try_for_each(|(src, dst)| encrypt(src, dst, password, iterations))
}

#[cfg(feature = "batch-ops")]
pub fn decrypt_batch<R, W>(batch: &mut [(R, W)], password: &PasswordString) -> Result<(), AescryptError>
where
    R: Read + Send,
    W: Write + Send,
{
    batch
        .par_iter_mut()
        .try_for_each(|(src, dst)| decrypt(src, dst, password))
}
