use std::io::{self, Read, Write};

use argon2::password_hash::rand_core::RngCore;
use argon_hash_password::{create_hash_and_salt, hash_and_verify, parse_saltstring};
use chacha20poly1305::{
    aead::{Aead, OsRng},
    KeyInit, XChaCha20Poly1305,
};
use zeroize::Zeroize;

const HASH_START_INDEX: usize = 48;
const HASH_STORED_SIZE: usize = 32;
const SALT_SIZE: usize = 22;
const NONCE_SIZE: usize = 24;

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

    w.write_all(&salt)?;
    w.write_all(&nonce)?;

    let aead = XChaCha20Poly1305::new(hash.as_ref().into());

    let mut buf = Vec::new();
    r.read_to_end(&mut buf)?;
    let v = aead.encrypt(nonce.as_ref().into(), &buf[..]).unwrap();
    w.write_all(&v)?;

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
    let mut buf = Vec::new();
    r.read_to_end(&mut buf)?;
    match aead.decrypt(nonce.as_ref().into(), &buf[..]) {
        Ok(v) => w.write_all(&v)?,
        Err(e) => {
            eprintln!("Incorrect password.");
            std::process::exit(1)
        }
    };

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
