pub mod handshake;
pub mod potfile;
pub use potfile::parsers::{hc_entry_parser, potfile_parser};

mod error;
pub use error::Error;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, Error>;
