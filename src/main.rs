use std::{
    fs::{self, File},
    io,
    path::PathBuf,
};

use crate::util::*;

mod util;

fn main() -> io::Result<()> {
    let mut args = std::env::args();
    let program = args.next().unwrap();

    let inpath = if let Some(a) = args.next() {
        PathBuf::from(a)
    } else {
        eprintln!("Usage: {} <FILE>", program);
        std::process::exit(1);
    };

    let password = rpassword::prompt_password("Password: ")?;

    let mut tmp = PathBuf::new();
    tmp.push("/tmp");
    tmp.push(format!(
        "{}-{}",
        rand_str(16),
        inpath.file_name().unwrap().to_string_lossy()
    ));

    // <Decrypt file>

    let mut tmpfile = File::create(&tmp)?;
    if inpath.exists() {
        // Decrypt the infile if it exists
        let mut infile = File::open(&inpath)?;
        decrypt(&password, &mut infile, &mut tmpfile)?;
        drop(infile);
    }
    drop(tmpfile);
    // </Decrypt file>

    scrawl::edit_file(&tmp).unwrap();

    // <Encrypt File>
    let mut tmpfile = File::open(&tmp)?;
    let mut infile = File::create(&inpath)?;

    encrypt(&password, &mut tmpfile, &mut infile)?;

    drop(tmpfile);
    drop(infile);
    // </Encrypt File>

    // Delete the tmp file
    fs::remove_file(tmp)?;
    Ok(())
}
