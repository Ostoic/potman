#![feature(drain_filter)]
#![deny(elided_lifetimes_in_paths)]

use clap::{Parser, Subcommand};
use potman::potfile::{HcEntry, HcSecret, Potfile};
use std::{
    collections::{HashMap, HashSet},
    fs,
};

#[derive(Debug, Parser)]
#[command(name = "potman")]
#[command(bin_name = "potman")]
#[command(about = "Hashcat potfile manager")]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Lookup {
        #[arg(short = 'p', help = "Path to the hashcat potfile", default_value_t = ("/home/owner/hashcat.potfile".to_string()))]
        potfile: String,

        #[arg(short = 'e', help = "The essid to use for the query")]
        essid: Option<String>,

        // #[arg(short = 'b', help = "The bssid to use for the query")]
        // bssid: Option<String>,

        #[arg(short = 'v', help = "Verbose logging", default_value_t = false)]
        verbose: bool,
    },

    Dump {
        #[arg(short = 'p', help = "Path to the hashcat potfile", default_value_t = ("/home/owner/hashcat.potfile".to_string()))]
        potfile: String,

        #[arg(short = 'v', help = "Verbose logging", default_value_t = false)]
        verbose: bool,

        #[arg(short = 's', help = "Dump all secrets in the given potfile", default_value_t = false)]
        secrets: bool,

        #[arg(short = 'e', help = "Dump all essids in the given potfile", default_value_t = false)]
        essids: bool,
    },
}

trait HasLen {
    fn len(&self) -> usize;
}

macro_rules! impl_haslen {
    ($name:ident $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?) => {
        impl$(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? HasLen for $name $(< $( $lt ),+ >)? {
            #[inline(always)]
            fn len(&self) -> usize {
                Self::len(self)
            }
        }
    };
}

impl_haslen!(HashMap<K, V, S>);
impl_haslen!(HashSet<T>);
impl_haslen!(Vec<T>);

#[inline]
fn plural(long: &impl HasLen) -> &'static str {
    match long.len() {
        0..=1 => "",
        _ => "s",
    }
}

fn lookup_by_essid(potfile: &Potfile<'_>, essid: &str, verbose: bool) {
    if verbose {
        println!("Lookup with {}", essid);
    }

    let Some(secrets) = potfile.lookup_secrets(essid)
        .map(Iterator::collect::<HashSet<_>>) else {
            println!("No secrets found!");
            return
        };

    if verbose {
        println!(
            "Found {} secret{} for {}: {:?}",
            secrets.len(),
            plural(&secrets),
            essid,
            secrets
        );
    } else {
        for secret in secrets {
            println!("{}", secret);
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Lookup {
            potfile,
            essid,
            // bssid,
            verbose,
        } => {
            let text = String::from_utf8(fs::read(potfile)?)?;
            let Ok((_, potfile)) = potman::potfile_parser(text.as_str()) else {
                panic!("Invalid potfile!")
            };

            if let Some(essid) = essid {
                if verbose {}

                lookup_by_essid(&potfile, essid.as_str(), verbose);
            }

            // if let Some(_bssid) = bssid {
            //     panic!("Bssid lookup not supported yet");
            //     // lookup_by_bssid(&potfile, &bssid);
            // }
        }
        Command::Dump {
            potfile,
            verbose,
            secrets,
            essids,
        } => {
            let text = String::from_utf8(fs::read(potfile)?)?;
            let Ok((_, potfile)) = potman::potfile_parser(text.as_str()) else {
                panic!("Invalid potfile!")
            };

            if secrets {
                dump_secrets(&potfile);
            } else if essids {
                dump_essids(&potfile);
            } else {
                dump_potfile(&potfile, verbose);
            }
        }
    }

    Ok(())
}

fn dump_essids(potfile: &Potfile<'_>) {
    for essid in potfile.entries.keys() {
        println!("{}", essid);
    }
}

fn dump_secrets(potfile: &Potfile<'_>) {
    let secrets: HashSet<_> = potfile
        .entries
        .iter_all()
        .flat_map(|(_, hs)| hs.iter().map(HcSecret::secret))
        .collect();

    for secret in secrets {
        println!("{}", secret);
    }
}

fn dump_potfile(potfile: &Potfile<'_>, verbose: bool) {
    if verbose {
        dbg!(&potfile);
    }

    for essid in potfile.entries.keys() {
        let Some(secrets) = potfile.lookup_secrets(essid.as_str())
            .map(Iterator::collect::<HashSet<_>>) else {
            continue
        };

        let Some(hs) = potfile.entries.get_vec(essid) else {
            continue
        };

        if verbose {
            println!(
                "'{}' has {} handshake{}, {} secret{}: {:?}",
                essid,
                hs.len(),
                plural(hs),
                secrets.len(),
                plural(&secrets),
                secrets
            );
        } else {
            for secret in secrets {
                println!("{}:{}", essid, secret);
            }
        }
    }
}
