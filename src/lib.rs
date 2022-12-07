#![cfg_attr(not(feature = "std"), no_std)]

pub mod handshake;
pub mod potfile;
pub use potfile::parsers::{hc_entry_parser, potfile_parser};

mod error;
pub use error::Error;

pub type Result<T> = core::result::Result<T, Error>;
