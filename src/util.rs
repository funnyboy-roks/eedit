use std::io::{self, Read, Write};

use argon2::password_hash::rand_core::RngCore;
use argon_hash_password::{create_hash_and_salt, hash_and_verify, parse_saltstring};
use chacha20poly1305::{
    aead::{stream, OsRng},
    KeyInit, XChaCha20Poly1305,
};
use zeroize::Zeroize;

const HASH_START_INDEX: usize = 48;
const HASH_STORED_SIZE: usize = 32;
const SALT_SIZE: usize = 22;
const NONCE_SIZE: usize = 19;

pub fn encrypt<R, W>(password: &str, r: &mut R, w: &mut W) -> io::Result<()>
where
    R: Read,
    W: Write,
{
    let mut nonce = [0u8; NONCE_SIZE];
    let mut hash = [0u8; HASH_STORED_SIZE];
    let mut salt = [0u8; SALT_SIZE];

    OsRng.fill_bytes(&mut nonce);

    let (hasha, salta) = create_hash_and_salt(password).unwrap();
    salt.copy_from_slice(salta.as_bytes());
    hash.copy_from_slice(&hasha.as_bytes()[HASH_START_INDEX..][..HASH_STORED_SIZE]);

    let aead = XChaCha20Poly1305::new(hash.as_ref().into());

    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    w.write_all(&salt)?;
    w.write_all(&nonce)?;

    let mut buf = [0u8; 1024];
    loop {
        let n = r.read(&mut buf)?;
        let v = stream_encryptor.encrypt_next(&buf[..n]).unwrap();
        w.write_all(&v)?;
        if n < buf.len() {
            break;
        }
    }

    hash.zeroize();
    buf.zeroize();

    Ok(())
}

pub fn decrypt<R, W>(password: &str, r: &mut R, w: &mut W) -> io::Result<()>
where
    R: Read,
    W: Write,
{
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    let mut hash = [0u8; HASH_STORED_SIZE];

    r.read_exact(&mut salt)?;
    r.read_exact(&mut nonce)?;

    let saltstring = parse_saltstring(std::str::from_utf8(&salt).unwrap()).unwrap();
    hash.copy_from_slice(
        &hash_and_verify(password, saltstring).unwrap().as_bytes()[HASH_START_INDEX..]
            [..HASH_STORED_SIZE],
    );

    let aead = XChaCha20Poly1305::new(hash.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buf = [0u8; 1024];
    loop {
        let n = r.read(&mut buf)?;
        let v = match stream_decryptor.decrypt_next(&buf[..n]) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("Incorrect password.");
                std::process::exit(1)
            }
        };
        w.write_all(&v)?;
        if n < buf.len() {
            break;
        }
    }

    hash.zeroize();
    buf.zeroize();

    Ok(())
}

const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub fn rand_str(len: usize) -> String {
    (0..len)
        .map(|_| CHARS[OsRng.next_u32() as usize % CHARS.len()] as char)
        .collect()
}
