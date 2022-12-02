#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Error {
    ParseError,
}
