#![deny(elided_lifetimes_in_paths)]

use clap::Parser;
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    potfile: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let bytes = fs::read(cli.potfile)?;
    let potfile_string = String::from_utf8(bytes)?;

    dbg!(&potfile_string);
    let Ok((_, potfile)) = potman::potfile_parser(potfile_string.as_str()) else {
        panic!("Invalid potfile")
    };

    dbg!(&potfile);
    println!("Parsed {} essids.", potfile.len());

    let multi_entries: Vec<_> = potfile
        .entries
        .iter_all()
        .filter(|(_, hs)| hs.len() > 1)
        .collect();

    println!("Essids with multiple handshakes:");
    for (essid, hs) in multi_entries {
        let Some(secrets): Option<Vec<_>> = potfile.lookup_secrets(essid)
            .map(Iterator::collect) else {
                continue
            };

        println!(
            "{} has {} handshakes, secrets: {:?}",
            essid,
            hs.len(),
            secrets
        );
    }

    Ok(())
}
