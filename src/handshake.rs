use macaddr::MacAddr6;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::{complete::hex_digit0, complete::hex_digit1},
    combinator::{complete, map, opt},
    sequence::{preceded, terminated, tuple},
    IResult,
};

use core::fmt;
use core::str::FromStr;

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ParseHandshakeError {
    InvalidPmkidLength,
    InvalidHandshakeType,
}

impl fmt::Display for ParseHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseHandshakeError {}

// static HCID_EMPTY: [u8; 16] = [0u8; 16];

macro_rules! make_hcid_type {
    ($name:ident) => {
        #[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
        pub struct $name([u8; 16]);

        impl From<[u8; 16]> for $name {
            #[inline]
            fn from(x: [u8; 16]) -> Self {
                Self(x)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = ParseHandshakeError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                if value.len() != core::mem::size_of::<$name>() {
                    Err(Self::Error::InvalidPmkidLength)
                } else {
                    // let x: *const [u8; 16] = value.as_ptr() as _;
                    let mut new: [u8; 16] = Default::default();
                    new.copy_from_slice(value);
                    Ok($name(new))
                }
            }
        }

        impl AsRef<[u8]> for $name {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }
    };
}

make_hcid_type!(Pmkid);
make_hcid_type!(EapolMic);

pub trait HcEssid {
    fn essid(&self) -> &str;
}

macro_rules! impl_hc_essid {
    ($t:ty) => {
        impl HcEssid for $t {
            #[inline]
            fn essid(&self) -> &str {
                self.essid.as_str()
            }
        }
    };
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PmkidHandshake {
    pmkid: Pmkid,
    bssid: MacAddr6,
    client_mac: MacAddr6,
    essid: String,
}

impl_hc_essid!(PmkidHandshake);

impl PmkidHandshake {
    #[inline]
    pub fn new(pmkid: Pmkid, bssid: MacAddr6, client_mac: MacAddr6, essid: String) -> Self {
        Self {
            pmkid,
            bssid,
            client_mac,
            essid,
        }
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for PmkidHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}*{}*{}*{}***",
            hex::encode(self.pmkid),
            hex::encode(self.bssid.as_bytes()),
            hex::encode(self.client_mac.as_bytes()),
            hex::encode(self.essid.as_bytes()),
        )
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Hc22000Kind {
    Pmkid = 1,
    Eapol = 2,
}

pub mod parsers {
    use nom::{
        bytes::complete::take_until1,
        combinator::opt,
        sequence::{delimited, terminated},
    };

    use super::*;
    pub fn macaddr6(input: &str) -> IResult<&str, MacAddr6> {
        use nom::{
            error::{Error, ErrorKind},
            Err,
        };

        let (o, mac_hexed) = hex_digit1(input)?;
        let mac = MacAddr6::from_str(mac_hexed)
            .map_err(|_| Err::Error(Error::new(o, ErrorKind::HexDigit)))?;

        Ok((o, mac))
    }

    const HCID_LEN: usize = 16;

    #[cfg(feature = "alloc")]
    pub fn handshake_id(input: &str) -> IResult<&str, [u8; HCID_LEN]> {
        use nom::{
            error::{Error, ErrorKind},
            Err,
        };

        let (o, hex) = hex_digit1(input)?;
        let bytes = hex::decode(hex).map_err(|_| Err::Error(Error::new(o, ErrorKind::HexDigit)))?;

        let mut result = <[u8; HCID_LEN]>::default();
        result.copy_from_slice(&bytes[..]);
        match bytes.len() == HCID_LEN {
            true => Ok((o, (result))),
            false => Err(Err::Error(Error::new(o, ErrorKind::HexDigit))),
        }
    }

    pub fn hc22000_kind(input: &str) -> IResult<&str, Hc22000Kind> {
        use nom::error::{Error, ErrorKind};

        let (o, r) = take_until1("*")(input)?;
        let kind = match r {
            "01" => Ok(Hc22000Kind::Pmkid),
            "02" => Ok(Hc22000Kind::Eapol),
            _ => Err(nom::Err::Error(Error::new(o, ErrorKind::Tag))),
        }?;

        Ok((o, (kind)))
    }

    #[cfg(feature = "alloc")]
    pub fn hexed_essid(i: &str) -> IResult<&str, String> {
        use nom::{
            error::{Error, ErrorKind},
            Err,
        };

        let (o, essid_hexed) = hex_digit1(i)?;
        let essid = hex::decode(essid_hexed)
            .map(String::from_utf8)
            .map_err(|_| Err::Error(Error::new(o, ErrorKind::HexDigit)))?
            .map_err(|_| Err::Error(Error::new(o, ErrorKind::HexDigit)))?;

        Ok((o, essid))
    }

    #[cfg(feature = "alloc")]
    pub fn hc22000_handshake(input: &str) -> IResult<&str, Hc22000> {
        let (o, (kind, id, bssid, client_mac, essid, ap_nonce, client_eapol, message_pair)) =
            tuple((
                delimited(terminated(tag("WPA"), tag("*")), hc22000_kind, tag("*")),
                terminated(handshake_id, tag("*")),
                terminated(macaddr6, tag("*")),    // ap mac
                terminated(macaddr6, tag("*")),    // client_mac mac
                terminated(hexed_essid, tag("*")), // essid
                terminated(complete(opt(hex_digit1)), tag("*")),
                terminated(complete(opt(hex_digit1)), tag("*")),
                complete(opt(hex_digit0)),
            ))(input)?;

        match kind {
            Hc22000Kind::Pmkid => Ok((
                o,
                Hc22000::Pmkid(PmkidHandshake::new(
                    Pmkid::from(id),
                    bssid,
                    client_mac,
                    essid,
                )),
            )),
            Hc22000Kind::Eapol => Ok((
                o,
                Hc22000::Eapol(EapolHandshake::new(
                    EapolMic::from(id),
                    bssid,
                    client_mac,
                    essid,
                    ap_nonce.unwrap().to_string(),
                    client_eapol.unwrap().to_string(),
                    message_pair.unwrap().to_string(),
                )),
            )),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EapolHandshake {
    mic: EapolMic,
    bssid: MacAddr6,
    client_mac: MacAddr6,
    essid: String,
    ap_nonce: String,
    client_eapol: String,
    message_pair: String,
}

impl_hc_essid!(EapolHandshake);

impl EapolHandshake {
    #[inline]
    pub fn new(
        mic: EapolMic,
        bssid: MacAddr6,
        client_mac: MacAddr6,
        essid: String,
        ap_nonce: String,
        client_eapol: String,
        message_pair: String,
    ) -> Self {
        Self {
            mic,
            bssid,
            client_mac,
            essid,
            ap_nonce,
            client_eapol,
            message_pair,
        }
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for EapolHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}*{}*{}*{}*{}*{}",
            hex::encode(self.bssid.as_bytes()),
            hex::encode(self.client_mac.as_bytes()),
            hex::encode(self.essid.as_bytes()),
            self.ap_nonce,
            self.client_eapol,
            self.message_pair
        )
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Hc22000 {
    Pmkid(PmkidHandshake),
    Eapol(EapolHandshake),
}

impl HcEssid for Hc22000 {
    #[inline]
    fn essid(&self) -> &str {
        match self {
            Hc22000::Pmkid(hs) => hs.essid(),
            Hc22000::Eapol(hs) => hs.essid(),
        }
    }
}

impl fmt::Display for Hc22000 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Hc22000::Pmkid(h) => write!(f, "WPA*01*{}", h),
            Hc22000::Eapol(h) => write!(f, "WPA*02*{}", h),
        }
    }
}

#[test]
#[cfg(test)]
#[cfg(feature = "alloc")]
fn test_hc22000() -> anyhow::Result<()> {
    {
        let line = "WPA*01*cc1e0bd250c425aa3165bb751773b2a6*1c772c6cbd78*b024aa14e22a*50515551***";
        let (_, parsed) = parsers::hc22000_handshake(line)?;
        let constructed = Hc22000::Pmkid(PmkidHandshake::new(
            Pmkid::try_from(hex::decode("cc1e0bd250c425aa3165bb751773b2a6")?.as_slice())?,
            MacAddr6::from_str("1c772c6cbd78")?,
            MacAddr6::from_str("b024aa14e22a")?,
            String::from_utf8(hex::decode("50515551")?)?,
        ));

        assert_eq!(constructed.to_string(), line);
        assert_eq!(constructed, (parsed));
    }
    {
        let line = "WPA*02*3e4cd510e3896cbe53ec0f3ac4d03171*00238c07c4ca*08df2f6ce442*6e6e65666c*70ce76710bcc3153979423faaf249b831274ada172ee1fcb5f322a0949bda670*0103007502010a0000000000000000ff7b4343f994791835d481590a0df01b4b759feb4a1582c731248a757e2f4f9aedcd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000*10";
        let (_, parsed) = parsers::hc22000_handshake(line)?;
        let constructed = Hc22000::Eapol(EapolHandshake::new(
            EapolMic::try_from(hex::decode("3e4cd510e3896cbe53ec0f3ac4d03171")?.as_slice())?,
            MacAddr6::from_str("00238c07c4ca")?,
            MacAddr6::from_str("08df2f6ce442")?,
            String::from_utf8(hex::decode("6e6e65666c")?)?,
            String::from("70ce76710bcc3153979423faaf249b831274ada172ee1fcb5f322a0949bda670"),
            String::from("0103007502010a0000000000000000ff7b4343f994791835d481590a0df01b4b759feb4a1582c731248a757e2f4f9aedcd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000"),
            String::from("10"),
        ));

        assert_eq!(constructed, parsed);
    }
    Ok(())
}

pub use parsers::hc22000_handshake as parse_hc22000;

use self::parsers::hexed_essid;

#[inline]
pub fn plaintext_essid_parser(input: &str) -> IResult<&str, String> {
    map(is_not("\r\n:"), String::from)(input)
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct LegacyHandshake {
    bssid: Option<MacAddr6>,
    client_mac: Option<MacAddr6>,
    essid: String,
}

impl HcEssid for LegacyHandshake {
    #[inline]
    fn essid(&self) -> &str {
        &self.essid[..]
    }
}

impl LegacyHandshake {
    #[inline]
    pub fn new(essid: impl Into<String>) -> Self {
        LegacyHandshake {
            essid: essid.into(),
            bssid: None,
            client_mac: None,
        }
    }
}

pub fn legacy_handshake_parser(input: &str) -> IResult<&str, LegacyHandshake> {
    let (o, essid) = preceded(
        tuple((
            terminated(complete(opt(hex_digit1)), tag(":")),
            terminated(complete(opt(parsers::macaddr6)), tag(":")),
            terminated(complete(opt(parsers::macaddr6)), tag(":")),
        )),
        alt((hexed_essid, plaintext_essid_parser)),
    )(input)?;

    Ok((o, LegacyHandshake::new(essid)))
}

#[test]
#[cfg(test)]
fn test_legacy_hs() {
    let tests = [
        (
            "",
            "44d1386cda1dca1a36d1a4e424cb127f:ccfe27b26042:ad1f441e1f86:C1AAEC1312AC",
        ),
        (
            "\r\n",
            "44d1386cda1dca1a36d1a4e424cb127f:ccfe27b26042:ad1f441e1f86:C1AAEC1312AC\r\n",
        ),
        ("\r\n", ":ccfe27b26042:ad1f441e1f86:C1AAEC1312AC\r\n"),
        ("\n", ":ccfe27b26042:ad1f441e1f86:C1AAEC1312AC\n"),
        (
            "\n",
            "44d1386cda1dca1a36d1a4e424cb127f:ccfe27b26042:ad1f441e1f86:C1AAEC1312AC\n",
        ),
    ];

    for (o_expected, test) in tests {
        let (o, hs) = legacy_handshake_parser(test).unwrap();
        dbg!(&o);
        dbg!(&hs);
        assert_eq!(o, o_expected);
    }
}
