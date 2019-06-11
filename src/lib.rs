//! Library for reading and writing Windows Registry files.

use encoding_rs::UTF_16LE;
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Binary(Vec<u8>),
    Dword(u32),
    Qword(u64),
    String(String),
    ExpandString(String),
    MultiString(Vec<String>),
    Link(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegFileVersion {
    Win95,
    Win2K,
    Wine2,
}

#[derive(Debug, Clone)]
pub struct RegKey {
    name: String,
    values: HashMap<String, RegValue>,
}

impl RegKey {
    pub fn get_root_value(&self) -> Option<&RegValue> {
        self.get_value("@")
    }

    pub fn get_value(&self, name: &str) -> Option<&RegValue> {
        self.values.get(name)
    }
}

impl ToString for RegKey {
    fn to_string(&self) -> String {
        let mut result = String::new();
        stringify::reg_key(self, &mut result);
        result
    }
}

#[derive(Debug, Clone)]
pub struct RegFile {
    version: RegFileVersion,
    keys: HashMap<String, RegKey>,
}

impl std::str::FromStr for RegFile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (remaining, regfile) = parse::reg_file(s).unwrap();
        if !remaining.is_empty() {
            Err(())
        } else {
            Ok(regfile)
        }
    }
}

impl ToString for RegFile {
    fn to_string(&self) -> String {
        let mut result = String::new();
        stringify::reg_file(self, &mut result);
        result
    }
}

const HEADER_WIN95: &str = "REGEDIT4\r\n";
const HEADER_WIN2K: &str = "Windows Registry Editor Version 5.00\r\n";
const HEADER_WINE2: &str = "WINE REGISTRY Version 2\n";

mod stringify {
    use super::{
        RegFile, RegFileVersion, RegKey, RegValue, HEADER_WIN2K, HEADER_WIN95, HEADER_WINE2,
    };
    use std::fmt::Write;

    fn header(version: RegFileVersion) -> &'static str {
        use RegFileVersion::*;
        match version {
            Win95 => HEADER_WIN95,
            Win2K => HEADER_WIN2K,
            Wine2 => HEADER_WINE2,
        }
    }

    fn reg_key_header(name: &str, output: &mut String) {
        write!(output, "[{}]", name).unwrap();
    }

    fn reg_value(value: &RegValue, output: &mut String) {
        match value {
            RegValue::Dword(n) => write!(output, "dword:{:08x}", n).unwrap(),
            RegValue::String(s) => write!(output, "\"{}\"", s).unwrap(),
            RegValue::Binary(v) => {
                output.push_str("hex:");
                for byte in v {
                    write!(output, "{:02x},", byte).unwrap();
                }
                output.pop();
            }
            _ => unimplemented!(),
        };
    }

    fn reg_value_line(name: &str, value: &RegValue, output: &mut String) {
        write!(output, r#""{}"="#, name).unwrap();
        reg_value(value, output);
    }

    fn reg_values<'a>(
        values: impl IntoIterator<Item = (&'a str, &'a RegValue)>,
        output: &mut String,
    ) {
        for (name, value) in values {
            reg_value_line(name, value, output);
        }
    }

    pub fn reg_key(key: &RegKey, output: &mut String) {
        reg_key_header(&key.name, output);
        reg_values(key.values.iter().map(|(n, v)| (&**n, v)), output);
    }

    pub fn reg_file(file: &RegFile, output: &mut String) {
        output.push_str(header(file.version));

        for key in file.keys.values() {
            reg_key(key, output);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn header_test() {
            let res = header(RegFileVersion::Win95);
            assert_eq!(res, "REGEDIT4\r\n");
            let res = header(RegFileVersion::Win2K);
            assert_eq!(res, "Windows Registry Editor Version 5.00\r\n");
            let res = header(RegFileVersion::Wine2);
            assert_eq!(res, "WINE REGISTRY Version 2\n");
        }

        #[test]
        fn reg_value_test() {
            let mut result = String::new();
            reg_value(&RegValue::Dword(1234), &mut result);
            assert_eq!(result, "dword:000004d2");
            result.clear();
            reg_value(&RegValue::String("abc".to_string()), &mut result);
            assert_eq!(result, "\"abc\"");
            result.clear();
            reg_value(&RegValue::Binary(vec![0, 1, 2, 3]), &mut result);
            assert_eq!(result, "hex:00,01,02,03");
            result.clear();
        }
    }
}

mod parse {
    use super::{
        RegFile, RegFileVersion, RegKey, RegValue, HEADER_WIN2K, HEADER_WIN95, HEADER_WINE2,
    };
    use nom::{
        branch::alt,
        bytes::complete::{is_not, tag, take_while, take_while_m_n},
        character::complete::{crlf, digit1, hex_digit1, newline},
        combinator::{map, map_res, opt},
        multi::{many0, separated_list},
        sequence::{delimited, pair, preceded, separated_pair, tuple},
        IResult,
    };
    use std::collections::HashMap;

    /// Determine the version of the file.
    fn header(input: &str) -> IResult<&str, RegFileVersion> {
        alt((
            map(tag(HEADER_WIN95), |_| RegFileVersion::Win95),
            map(tag(HEADER_WIN2K), |_| RegFileVersion::Win2K),
            map(tag(HEADER_WINE2), |_| RegFileVersion::Wine2),
        ))(input)
    }

    /// Take and discard all whitespace characters.
    fn skip_whitespace(input: &str) -> IResult<&str, ()> {
        let (input, _) = take_while(char::is_whitespace)(input)?;
        Ok((input, ()))
    }

    /// Match an end-of-line sequence: LF for Wine registry hives, CRLF for Windows.
    fn eol(version: RegFileVersion) -> impl Fn(&str) -> IResult<&str, ()> {
        move |input: &str| {
            if version == RegFileVersion::Wine2 {
                let (input, _) = newline(input)?;
                Ok((input, ()))
            } else {
                let (input, _) = crlf(input)?;
                Ok((input, ()))
            }
        }
    }

    /// Read a registry key header: [HKEY_ROOT\KeyName]
    ///
    /// In Wine registry hives, key headers have a bunch of additional data that we'll ignore.
    fn reg_key_header(version: RegFileVersion) -> impl Fn(&str) -> IResult<&str, &str> {
        move |input: &str| {
            let (input, _) = skip_whitespace(input)?;
            let (input, key) = delimited(tag("["), is_not("]"), tag("]"))(input)?;

            let input = if version == RegFileVersion::Wine2 {
                let (input, _) = skip_whitespace(input)?;
                let (input, _) = digit1(input)?;
                let (input, _) = newline(input)?;
                let (input, _) = tag("#time=")(input)?;
                let (input, _) = hex_digit1(input)?;
                input
            } else {
                input
            };

            let (input, _) = eol(version)(input)?;

            Ok((input, key))
        }
    }

    fn quoted_string(input: &str) -> IResult<&str, &str> {
        delimited(tag("\""), is_not("\""), tag("\""))(input)
    }

    /// Read a hex byte, two hexadecimal characters.
    fn hex_byte(input: &str) -> IResult<&str, u8> {
        fn is_hex_digit(c: char) -> bool {
            c.is_digit(16)
        }

        map_res(take_while_m_n(2, 2, is_hex_digit), |s| {
            u8::from_str_radix(s, 16)
        })(input)
    }

    fn reg_value(version: RegFileVersion) -> impl Fn(&str) -> IResult<&str, RegValue> {
        move |input: &str| {
            let dword = preceded(
                tag("dword:"),
                map_res(hex_digit1, |s| {
                    u32::from_str_radix(s, 16).map(RegValue::Dword)
                }),
            );

            let comma_opt_newl = pair(
                tag(","),
                opt(tuple((tag("\\"), eol(version), skip_whitespace))),
            );

            let binary = preceded(
                tag("hex:"),
                map(separated_list(comma_opt_newl, hex_byte), RegValue::Binary),
            );

            let string = map(quoted_string, |s| RegValue::String(s.to_string()));

            alt((dword, string, binary))(input)
        }
    }

    fn reg_value_line(version: RegFileVersion) -> impl Fn(&str) -> IResult<&str, (&str, RegValue)> {
        move |input: &str| {
            let (input, tuple) =
                separated_pair(quoted_string, tag("="), reg_value(version))(input)?;
            let (input, _) = eol(version)(input)?;

            Ok((input, tuple))
        }
    }

    fn reg_values(
        version: RegFileVersion,
    ) -> impl Fn(&str) -> IResult<&str, Vec<(&str, RegValue)>> {
        move |input: &str| {
            let (input, values) = many0(reg_value_line(version))(input)?;
            Ok((input, values))
        }
    }

    fn reg_key(version: RegFileVersion) -> impl Fn(&str) -> IResult<&str, RegKey> {
        move |input: &str| {
            let (input, name) = reg_key_header(version)(input)?;
            let (input, values) = reg_values(version)(input)?;
            let (input, _) = eol(version)(input)?;

            let mut values_map = HashMap::new();
            for (name, val) in values {
                values_map.insert(name.to_string(), val);
            }

            Ok((
                input,
                RegKey {
                    name: name.to_string(),
                    values: values_map,
                },
            ))
        }
    }

    pub fn reg_file(input: &str) -> IResult<&str, RegFile> {
        let (input, version) = header(input)?;

        let (input, keys) = many0(reg_key(version))(input)?;

        let mut keys_map = HashMap::new();
        for key in keys {
            // eh can this be done without the clone
            keys_map.insert(key.name.clone(), key);
        }

        Ok((
            input,
            RegFile {
                version,
                keys: keys_map,
            },
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn header_test() {
            let (_, res) = header("REGEDIT4\r\n").unwrap();
            assert_eq!(res, RegFileVersion::Win95);
            let (_, res) = header("Windows Registry Editor Version 5.00\r\n").unwrap();
            assert_eq!(res, RegFileVersion::Win2K);
            let (_, res) = header("WINE REGISTRY Version 2\n").unwrap();
            assert_eq!(res, RegFileVersion::Wine2);
        }

        #[test]
        fn reg_key_header_test() {
            let (_, res) = reg_key_header(RegFileVersion::Win2K)("[HKEY_CURRENT_USER\\Software\\Microsoft\\Microsoft Games\\Age of Empires II: The Conquerors Expansion]\r\n").unwrap();
            assert_eq!(res, r"HKEY_CURRENT_USER\Software\Microsoft\Microsoft Games\Age of Empires II: The Conquerors Expansion");
        }

        #[test]
        fn reg_value_test() {
            let (_, res) = reg_value(RegFileVersion::Win2K)("dword:0000000f").unwrap();
            assert_eq!(res, RegValue::Dword(0x0f));
            let (_, res) = reg_value(RegFileVersion::Win2K)("\"192.168.178.116\"").unwrap();
            assert_eq!(res, RegValue::String("192.168.178.116".to_string()));
            let (_, res) = reg_value(RegFileVersion::Win2K)("hex:30,00,00,80,10,00,00,00").unwrap();
            assert_eq!(
                res,
                RegValue::Binary(vec![0x30, 0x00, 0x00, 0x80, 0x10, 0x00, 0x00, 0x00]),
                "hex value"
            );
            let (_, res) =
                reg_value(RegFileVersion::Win2K)("hex:30,00,00,80,\\\r\n  10,00,00,00").unwrap();
            assert_eq!(
                res,
                RegValue::Binary(vec![0x30, 0x00, 0x00, 0x80, 0x10, 0x00, 0x00, 0x00]),
                "multiline hex value"
            );
            let (_, res) =
                reg_value(RegFileVersion::Win2K)(r#""C:\\users\\goto-bus-stop\\Temp""#).unwrap();
            assert_eq!(
                res,
                RegValue::String(r"C:\users\goto-bus-stop\Temp".to_string()),
                "unescape values"
            );
        }

        #[test]
        fn reg_value_line_test() {
            let (_, res) =
                reg_value_line(RegFileVersion::Win2K)("\"Spec Default\"=dword:00000000\r\n")
                    .unwrap();
            assert_eq!(res, ("Spec Default", RegValue::Dword(0)));
            let (_, res) =
                reg_value_line(RegFileVersion::Win2K)("\"Spectate IP\"=\"192.168.178.116\"\r\n")
                    .unwrap();
            assert_eq!(
                res,
                (
                    "Spectate IP",
                    RegValue::String("192.168.178.116".to_string())
                )
            );
        }

        #[test]
        fn reg_key_test() {
            let (_, key) = reg_key(RegFileVersion::Win2K)("[HKEY_CURRENT_USER\\Software\\Microsoft\\Microsoft Games\\Age of Empires II: The Conquerors Expansion\\1.0\\EULA]\r\n\"FIRSTRUN\"=dword:00000001\r\n\r\n").unwrap();
            assert_eq!(key.name, r"HKEY_CURRENT_USER\Software\Microsoft\Microsoft Games\Age of Empires II: The Conquerors Expansion\1.0\EULA");
            let mut values = HashMap::new();
            values.insert("FIRSTRUN".to_string(), RegValue::Dword(1));
            assert_eq!(key.values, values);
        }

        #[test]
        fn reg_file_test() {
            use encoding_rs::UTF_16LE;
            let file = std::fs::read("test/input.reg").unwrap();
            let utf8 = UTF_16LE.decode(&file).0;
            reg_file(&utf8).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
