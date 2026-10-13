//! `aescrypt-cli`: encrypt and decrypt AES Crypt files from the command line.
//! The implementation lives in the crate's library target; see the README.

#![forbid(unsafe_code)]

fn main() {
    std::process::exit(aescrypt_cli::main_entry());
}
