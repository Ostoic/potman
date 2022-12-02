use multimap::MultiMap;

use crate::handshake::{Hc22000, HcEssid, LegacyHandshake};

use core::fmt;

pub trait PotfileLookup {}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Potfile<'a> {
    pub entries: MultiMap<String, HcEntry<'a>>,
}

impl<'a> Potfile<'a> {
    // TODO: Handle duplicate handshakes and duplicate entries (potentially different bssids)
    #[inline]
    pub fn lookup_secret(&self, essid: &str) -> Option<HcPassword> {
        self.entries.get(essid).map(HcSecret::secret)
    }

    #[inline]
    pub fn lookup_secrets(&self, essid: &str) -> Option<impl Iterator<Item = HcPassword>> {
        self.entries
            .get_vec(essid)
            .map(|v| v.iter().map(HcSecret::secret))
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<'a> fmt::Display for Potfile<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (_, entry) in &self.entries {
            for hs in entry {
                writeln!(f, "{}", hs)?;
            }
        }

        write!(f, "")
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Ord, PartialOrd, Clone)]
pub struct HcPassword<'a>(&'a str);

pub trait HcSecret {
    fn secret(&self) -> HcPassword;
}

impl<'a> HcSecret for HcPassword<'a> {
    #[inline]
    fn secret(&self) -> HcPassword {
        self.clone()
    }
}

impl<'a> fmt::Display for HcPassword<'a> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct Hc22000Entry<'a> {
    pub handshake: Hc22000,
    pub secret: HcPassword<'a>,
}

impl<'a> HcSecret for Hc22000Entry<'a> {
    #[inline]
    fn secret(&self) -> HcPassword {
        self.secret.clone()
    }
}

impl<'a> HcEssid for Hc22000Entry<'a> {
    #[inline]
    fn essid(&self) -> &str {
        self.handshake.essid()
    }
}

impl<'a> fmt::Display for Hc22000Entry<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.handshake, self.secret)
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct LegacyEntry<'a> {
    handshake: LegacyHandshake,
    secret: HcPassword<'a>,
}

impl<'a> HcSecret for LegacyEntry<'a> {
    #[inline]
    fn secret(&self) -> HcPassword {
        self.secret.clone()
    }
}

impl<'a> HcEssid for LegacyEntry<'a> {
    #[inline]
    fn essid(&self) -> &str {
        self.handshake.essid()
    }
}

impl<'a> fmt::Display for LegacyEntry<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, ":::{}:{}", self.essid(), self.secret)
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub enum HcEntry<'a> {
    Legacy(LegacyEntry<'a>),
    Hc22000(Hc22000Entry<'a>),
}

impl<'a> HcSecret for HcEntry<'a> {
    #[inline]
    fn secret(&self) -> HcPassword {
        match self {
            HcEntry::Legacy(e) => e.secret(),
            HcEntry::Hc22000(e) => e.secret(),
        }
    }
}

impl<'a> HcEssid for HcEntry<'a> {
    #[inline]
    fn essid(&self) -> &str {
        match self {
            HcEntry::Legacy(e) => e.essid(),
            HcEntry::Hc22000(e) => e.essid(),
        }
    }
}

impl<'a> fmt::Display for HcEntry<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HcEntry::Hc22000(hc22000) => write!(f, "{}", hc22000),
            HcEntry::Legacy(plaintext) => write!(f, "{}", plaintext),
        }
    }
}

pub mod parsers {
    use crate::handshake::legacy_handshake_parser;

    use super::*;
    use nom::{
        branch::alt,
        bytes::{complete::is_not, streaming::tag},
        combinator::{complete, map, opt},
        sequence::{pair, preceded, terminated},
        IResult,
    };

    #[inline]
    pub fn hc_password_parser(input: &str) -> IResult<&str, HcPassword> {
        is_not("\r\n")(input).map(|(o, p)| (o, HcPassword(p)))
    }

    #[inline]
    pub fn hc22000_entry_parser(input: &str) -> IResult<&str, Hc22000Entry> {
        use crate::handshake::parse_hc22000;
        let (o, handshake) = parse_hc22000(input)?;
        let (o, password) = preceded(tag(":"), hc_password_parser)(o)?;

        Ok((
            o,
            Hc22000Entry {
                handshake,
                secret: password,
            },
        ))
    }

    #[inline]
    pub fn legacy_entry_parser(input: &str) -> IResult<&str, LegacyEntry> {
        let (o, (handshake, password)) = pair(
            terminated(legacy_handshake_parser, tag(":")),
            hc_password_parser,
        )(input)?;

        Ok((
            o,
            LegacyEntry {
                handshake,
                secret: password,
            },
        ))
    }

    #[inline]
    pub fn hc_entry_parser(input: &str) -> IResult<&str, HcEntry> {
        let (o, result) = complete(opt(legacy_entry_parser))(input)?;
        match result {
            None => map(hc22000_entry_parser, HcEntry::Hc22000)(o),
            Some(entry) => Ok((o, HcEntry::Legacy(entry))),
        }
    }

    #[inline]
    #[cfg(feature = "alloc")]
    // NOTE: Care is needed for opt parsers (needs to know if it's complete or not)
    pub fn potfile_parser(input: &str) -> IResult<&str, Potfile> {
        use nom::multi::separated_list0;
        let (o, list) = separated_list0(
            complete(opt(alt((tag("\r\n"), tag("\n"))))),
            hc_entry_parser,
        )(input)?;

        let mut entries = MultiMap::with_capacity(list.len() / 2);
        for entry in list {
            entries.insert(entry.essid().to_string(), entry);
        }

        Ok((o, Potfile { entries }))
        // .map(|(o, entries)| (o, Potfile { entries }))
    }
}

#[cfg(test)]
const PMKID_HS: &str =
    "WPA*01*cc1e0bd250c425aa3165bb751773b2a6*1c772c6cbd78*b024aa14e22a*50515551***";

#[cfg(test)]
const EAPOL_HS: &str = "WPA*02*3e4cd510e3896cbe53ec0f3ac4d03171*00238c07c4ca*08df2f6ce442*6e6e65666c*70ce76710bcc3153979423faaf249b831274ada172ee1fcb5f322a0949bda670*0103007502010a0000000000000000ff7b4343f994791835d481590a0df01b4b759feb4a1582c731248a757e2f4f9aedcd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000*10";

#[cfg(test)]
const PLAINTEXT_ENTRY: &str = ":::dlink-BCDA:plaintext";

#[test]
#[cfg(test)]
fn test_pot_hcentry() {
    use crate::potfile::parsers::hc_entry_parser;

    let (_, parsed_hs) = crate::handshake::parse_hc22000(PMKID_HS).unwrap();
    assert_eq!(format!("{}", parsed_hs), PMKID_HS);

    let potfile_text = format!(
        "{}:testpass\n{}\n{}:testpass2",
        PMKID_HS, PLAINTEXT_ENTRY, EAPOL_HS,
    );

    // TODO: verify handshakes as well
    let mut lines = potfile_text.split('\n');
    let Ok((_, HcEntry::Hc22000(entry1))) = hc_entry_parser(lines.next().unwrap()) else {
        panic!("Expected hc22000 entry")
    };

    dbg!(&entry1);
    let Ok((_, HcEntry::Legacy(entry2))) = hc_entry_parser(lines.next().unwrap()) else {
        panic!("Expected plaintext entry")
    };

    dbg!(&entry2);
    dbg!(&lines);
    let Ok((_, HcEntry::Hc22000(entry3))) = hc_entry_parser(lines.next().unwrap()) else {
        panic!("Expected hc22000 entry")
    };

    assert_eq!(entry1.essid(), "PQUQ");
    assert_eq!(entry1.secret(), HcPassword("testpass"));
    assert_eq!(entry2.essid(), "dlink-BCDA");
    assert_eq!(entry2.secret(), HcPassword("plaintext"));
    assert_eq!(entry3.essid(), "nnefl");
    assert_eq!(entry3.secret(), HcPassword("testpass2"));
}

#[test]
#[cfg(test)]
fn test_plaintext_entry() {
    use self::parsers::legacy_entry_parser;
    let line = format!("{}\n", PLAINTEXT_ENTRY);

    let (o, entry) = legacy_entry_parser(line.as_str()).unwrap();
    assert_eq!(o.chars().next().unwrap(), '\n');
    assert_eq!(
        entry,
        LegacyEntry {
            handshake: LegacyHandshake::new("dlink-BCDA"),
            secret: HcPassword("plaintext".into())
        }
    );
}

#[test]
#[cfg(test)]
fn test_hc_entry() {
    use self::parsers::hc_entry_parser;
    let input1 =
        "WPA*01*cc1e0bd250c425aa3165bb751773b2a6*1c772c6cbd78*b024aa14e22a*50515551***:manman\n";

    let input2 = ":::dlink-ABCD:12345678";
    let (o1, entry1) = hc_entry_parser(input1).unwrap();
    let (o2, entry2) = hc_entry_parser(input2).unwrap();
    assert_eq!(o1, "\n");
    assert!(o2.is_empty());

    match entry1 {
        HcEntry::Hc22000(hc22000) => assert_eq!(hc22000.secret.0, "manman"),
        HcEntry::Legacy(_) => assert!(false),
    };

    match entry2 {
        HcEntry::Hc22000(_) => assert!(false),
        HcEntry::Legacy(plain) => {
            assert_eq!(plain.essid(), "dlink-ABCD");
            assert_eq!(plain.secret.0, "12345678");
        }
    };
}

#[test]
#[cfg(test)]
fn test_potfile() -> anyhow::Result<()> {
    use self::parsers::potfile_parser;
    let eapol_entry = format!("{}:testpass23", EAPOL_HS);
    let legacy1 = String::from(":::dlink-ABCD:12345678");

    let tests = [
        [eapol_entry.clone(), legacy1.clone()].join("\n"),
        [eapol_entry.clone(), legacy1.clone()].join("\r\n"),
        [eapol_entry.clone(), format!("{}\n", legacy1.clone())].join("\r\n"),
        [eapol_entry.clone(), format!("{}\r\n", legacy1.clone())].join("\r\n"),
        [eapol_entry.clone(), format!("{}\r\n", legacy1.clone())].join("\r\n"),
        [eapol_entry.clone(), format!("{}\r\n", legacy1.clone())].join("\n"),
    ];

    for lines in tests {
        dbg!(&lines);
        let (o, potfile) = potfile_parser(lines.as_str()).unwrap();

        dbg!(&o);
        dbg!(&potfile);
        assert_eq!(potfile.entries.len(), 2);
        let HcEntry::Hc22000(hc22000) = &potfile.entries["nnefl"] else {
            panic!("Expected hc22000 entry")
        };
        assert_eq!(hc22000.secret(), HcPassword("testpass23"));

        let HcEntry::Legacy(legacy) = &potfile.entries["dlink-ABCD"] else {
            panic!("Expected legacy entry")
        };
        assert_eq!(legacy.secret(), HcPassword("12345678"));

        assert_eq!(
            potfile.lookup_secret("dlink-ABCD"),
            Some(HcPassword("12345678"))
        );
        assert_eq!(
            potfile.lookup_secret("nnefl"),
            Some(HcPassword("testpass23"))
        );
    }

    {
        let (o, potfile) =
            potfile_parser(":2c9066e31d42:b015aa8c61c2:4d616e6d616e3233:america123\r\n").unwrap();
        assert_eq!(o, "\r\n");
        assert_eq!(
            potfile.lookup_secret("Manman23"),
            Some(HcPassword("america123"))
        );
    }
    Ok(())
}
