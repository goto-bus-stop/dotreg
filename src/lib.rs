//! Library for reading and writing Windows Registry files.

use encoding_rs::UTF_16LE;
use std::collections::HashMap;

/// A typed registry value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    /// Arbitrary bytes.
    Binary(Vec<u8>),
    /// 32-bit integer.
    Dword(u32),
    /// 64-bit integer.
    Qword(u64),
    /// A string.
    String(String),
    /// A string with %VARS% that should be expanded.
    ExpandString(String),
    /// Multiple strings.
    MultiString(Vec<String>),
    /// A symbolic link to another registry key.
    Link(String),
    Deletion,
}

/// A registry file format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegFileVersion {
    /// The regedit file format used by Windows versions before Windows 2000.
    Win95,
    /// The regedit file format used by Windows versions from Windows 2000 on.
    Win2K,
    /// The file format used by Wine for its registry storage.
    Wine2,
}

/// A registry key, with a name and a bunch of values.
#[derive(Debug, Clone)]
pub struct RegKey {
    /// Name of the key.
    name: String,
    /// Values.
    values: HashMap<String, RegValue>,
}

impl RegKey {
    /// Create a new empty registry key.
    pub fn new(name: String) -> RegKey {
        RegKey {
            name,
            values: Default::default(),
        }
    }

    /// Create a symbolic link to some other key.
    pub fn new_link(name: String, target: &str) -> RegKey {
        let mut key = RegKey::new(name);
        key.set_link_target(target);
        key
    }

    /// Get the root value (@) of this key.
    pub fn get_root_value(&self) -> Option<&RegValue> {
        self.get_value("@")
    }

    /// Get a value from this key.
    pub fn get_value(&self, name: &str) -> Option<&RegValue> {
        self.values.get(name)
    }

    pub fn set_root_value(&mut self, value: RegValue) {
        self.set_value("@", value);
    }

    pub fn set_value(&mut self, name: &str, value: RegValue) {
        self.values.insert(name.to_string(), value);
    }

    /// Is this key a symbolic link?
    pub fn is_link(&self) -> bool {
        if self.values.len() != 1 {
            return false;
        }
        self.get_value("SymbolicLinkValue")
            .map(|val| match val {
                RegValue::Link(_) => true,
                _ => false,
            })
            .unwrap_or(false)
    }

    /// If this key is a symbolic link, get the path to the key it targets.
    pub fn link_target(&self) -> Option<&str> {
        self.get_value("SymbolicLinkValue")
            .and_then(|val| match val {
                RegValue::Link(path) => Some(&**path),
                _ => None,
            })
    }

    pub fn set_link_target(&mut self, target: &str) {
        self.set_value("SymbolicLinkValue", RegValue::Link(target.into()));
    }
}

impl ToString for RegKey {
    /// Serialize a registry key to the Win2K format.
    fn to_string(&self) -> String {
        let mut result = String::new();
        stringify::reg_key(self, &mut result);
        result
    }
}

/// A registry file containing registry keys.
#[derive(Debug, Clone)]
pub struct RegFile {
    /// The version of the file.
    version: RegFileVersion,
    /// The keys in this file.
    keys: HashMap<String, RegKey>,
}

impl RegFile {
    pub fn version(&self) -> RegFileVersion {
        self.version
    }

    pub fn keys(&self) -> impl Iterator<Item = &RegKey> {
        self.keys.values()
    }

    pub fn keys_mut(&mut self) -> impl Iterator<Item = &mut RegKey> {
        self.keys.values_mut()
    }

    pub fn add(&mut self, key: RegKey) {
        self.keys.insert(key.name.clone(), key);
    }

    pub fn create_key(&mut self, name: &str) -> &mut RegKey {
        let key = RegKey::new(name.to_string());
        self.add(key);
        self.get_key_mut(name).unwrap()
    }

    pub fn get_key(&self, name: &str) -> Option<&RegKey> {
        self.keys.get(name)
    }

    pub fn get_key_mut(&mut self, name: &str) -> Option<&mut RegKey> {
        self.keys.get_mut(name)
    }
}

#[derive(Debug)]
pub enum ParseRegFileError {
    /// An error occurred while reading data.
    IoError(std::io::Error),
    /// Tried to read a string but it was not in the expected encoding (usually UTF-16).
    EncodingError,
    ParseError,
    /// The string was not fully parsed.
    TrailingData,
    // TrailingData(&str, RegFile),
}

impl std::str::FromStr for RegFile {
    type Err = ParseRegFileError;

    /// Parse a registry file from a UTF-8 string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (remaining, regfile) = parse::reg_file(s).map_err(|_| ParseRegFileError::ParseError)?;
        if !remaining.is_empty() {
            Err(ParseRegFileError::TrailingData)
        // Err(ParseRegFileError::TrailingData(remaining, regfile))
        } else {
            Ok(regfile)
        }
    }
}

impl ToString for RegFile {
    /// Serialize a registry file to the Win2K format.
    fn to_string(&self) -> String {
        let mut result = String::new();
        stringify::reg_file(self, &mut result);
        result
    }
}

/// Read and parse a registry file from a byte stream.
pub fn read(mut input: impl std::io::Read) -> Result<RegFile, ParseRegFileError> {
    let mut bytes = vec![];
    input
        .read_to_end(&mut bytes)
        .map_err(ParseRegFileError::IoError)?;
    let (s, _, failed) = UTF_16LE.decode(&bytes);
    if failed {
        return Err(ParseRegFileError::EncodingError);
    }

    s.parse()
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
        if name == "@" {
            output.push_str("@=");
        } else {
            write!(output, r#""{}"="#, name).unwrap();
        }
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
    use encoding_rs::UTF_16LE;
    use nom::{
        branch::alt,
        bytes::complete::{escaped_transform, is_not, tag, take_while, take_while_m_n},
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

    fn quoted_string(input: &str) -> IResult<&str, String> {
        let middle = escaped_transform(is_not(r#"\""#), '\\', |esc: &str| {
            match esc.chars().next() {
                Some('\\') => Ok((&esc[1..], "\\")),
                Some('"') => Ok((&esc[1..], "\"")),
                Some('r') => Ok((&esc[1..], "\r")),
                Some('n') => Ok((&esc[1..], "\n")),
                _ => Ok((esc, "\\")),
            }
        });
        delimited(tag("\""), middle, tag("\""))(input)
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

            let comma_opt_newl = || {
                pair(
                    tag(","),
                    opt(tuple((tag("\\"), eol(version), skip_whitespace))),
                )
            };

            let binary = preceded(
                tag("hex:"),
                map(separated_list(comma_opt_newl(), hex_byte), RegValue::Binary),
            );

            let string = map(quoted_string, |s| RegValue::String(s.to_string()));

            fn parse_expand_string(mut bytes: Vec<u8>) -> RegValue {
                if bytes.ends_with(&[0, 0]) {
                    bytes.pop();
                    bytes.pop();
                }
                let (s, _, failed) = UTF_16LE.decode(&bytes);
                if failed {
                    eprintln!("{:?}", bytes);
                    panic!("should do something useful here")
                }

                RegValue::ExpandString(s.to_string())
            }

            let expand_string = preceded(
                tag("hex(2):"),
                // TODO switch to map_res
                map(
                    separated_list(comma_opt_newl(), hex_byte),
                    parse_expand_string,
                ),
            );

            /// Parse bytes into a list of strings.
            ///
            /// Strings are separated by two NUL bytes. The list end is marked by an empty string,
            /// i.e. four subsequent NUL bytes total.
            fn parse_multi_string(bytes: Vec<u8>) -> RegValue {
                let mut strings = vec![];
                let mut iter = bytes.iter();
                let mut last_index = 0;
                let mut index = 0;
                loop {
                    match (iter.next(), iter.next()) {
                        (Some(0), Some(0)) => {
                            if index == last_index {
                                break;
                            }

                            let (s, _, failed) = UTF_16LE.decode(&bytes[last_index..index]);
                            if failed {
                                panic!("should do something useful here")
                            }
                            strings.push(s.to_string());
                            last_index = index + 2;
                        }
                        (Some(_), Some(_)) => {}
                        (Some(_), None) => panic!("uneven number of bytes"),
                        (None, None) => panic!("expected to find four NULs at the end"),
                        (None, Some(_)) => unreachable!(),
                    }
                    index += 2;
                }

                RegValue::MultiString(strings)
            }

            let multi_string = preceded(
                tag("hex(7):"),
                // TODO switch to map_res
                map(
                    separated_list(comma_opt_newl(), hex_byte),
                    parse_multi_string,
                ),
            );

            fn parse_link(bytes: Vec<u8>) -> RegValue {
                let (s, _, failed) = UTF_16LE.decode(&bytes);
                if failed {
                    eprintln!("{:?}", bytes);
                    panic!("should do something useful here")
                }

                RegValue::Link(s.to_string())
            }

            let link = preceded(
                tag("hex(6):"),
                // TODO switch to map_res
                map(separated_list(comma_opt_newl(), hex_byte), parse_link),
            );

            let delete = map(tag("-"), |_| RegValue::Deletion);

            alt((
                dword,
                binary,
                expand_string,
                multi_string,
                link,
                string,
                delete,
            ))(input)
        }
    }

    fn reg_value_name(input: &str) -> IResult<&str, String> {
        quoted_string(input).or_else(move |_| map(tag("@"), ToString::to_string)(input))
    }

    fn reg_value_line(
        version: RegFileVersion,
    ) -> impl Fn(&str) -> IResult<&str, (String, RegValue)> {
        move |input: &str| {
            let (input, tuple) =
                separated_pair(reg_value_name, tag("="), reg_value(version))(input)?;
            let (input, _) = eol(version)(input)?;

            Ok((input, tuple))
        }
    }

    fn reg_values(
        version: RegFileVersion,
    ) -> impl Fn(&str) -> IResult<&str, Vec<(String, RegValue)>> {
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
            // meh, can this be done without the clone?
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
            let (_, res) = reg_value(RegFileVersion::Win2K)("hex(2):43,00,3a,00,5c,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,20,00,46,\\\r\n00,69,00,6c,00,65,00,73,00,5c,00,49,00,6e,00,74,00,65,00,72,00,6e,00,65,00,\\\r\n74,00,20,00,45,00,78,00,70,00,6c,00,6f,00,72,00,65,00,72,00,5c,00,69,00,65,\\\r\n00,78,00,70,00,6c,00,6f,00,72,00,65,00,2e,00,65,00,78,00,65,00,2c,00,31,00,\\\r\n00,00").unwrap();
            assert_eq!(
                res,
                RegValue::ExpandString(
                    r"C:\Program Files\Internet Explorer\iexplore.exe,1".to_string()
                )
            );
            let (_, res) = reg_value(RegFileVersion::Win2K)("hex(6):5c,00,52,00,65,00,67,00,69,00,73,00,74,00,72,00,79,\\\r\n00,5c,00,4d,00,61,00,63,00,68,00,69,00,6e,00,65,00,5c,00,53,00,6f,00,66,00,\\\r\n74,00,77,00,61,00,72,00,65,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,\\\r\n00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,4e,00,\\\r\n54,00,5c,00,43,00,75,00,72,00,72,00,65,00,6e,00,74,00,56,00,65,00,72,00,73,\\\r\n00,69,00,6f,00,6e,00,5c,00,49,00,6d,00,61,00,67,00,65,00,20,00,46,00,69,00,\\\r\n6c,00,65,00,20,00,45,00,78,00,65,00,63,00,75,00,74,00,69,00,6f,00,6e,00,20,\\\r\n00,4f,00,70,00,74,00,69,00,6f,00,6e,00,73,00").unwrap();
            assert_eq!(res, RegValue::Link(r"\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options".to_string().into()));
            let (_, res) = reg_value(RegFileVersion::Win2K)("hex(7):4d,00,53,00,47,00,4f,00,54,00,48,00,49,00,43,00,\\\r\n2e,00,54,00,54,00,43,00,2c,00,4d,00,53,00,20,00,55,00,49,00,20,00,47,00,6f,\\\r\n00,74,00,68,00,69,00,63,00,00,00,4d,00,49,00,4e,00,47,00,4c,00,49,00,55,00,\\\r\n2e,00,54,00,54,00,43,00,2c,00,50,00,4d,00,69,00,6e,00,67,00,4c,00,69,00,55,\\\r\n00,00,00,53,00,49,00,4d,00,53,00,55,00,4e,00,2e,00,54,00,54,00,43,00,2c,00,\\\r\n53,00,69,00,6d,00,53,00,75,00,6e,00,00,00,47,00,55,00,4c,00,49,00,4d,00,2e,\\\r\n00,54,00,54,00,43,00,2c,00,47,00,75,00,6c,00,69,00,6d,00,00,00,00,00").unwrap();
            assert_eq!(
                res,
                RegValue::MultiString(vec![
                    "MSGOTHIC.TTC,MS UI Gothic".to_string(),
                    "MINGLIU.TTC,PMingLiU".to_string(),
                    "SIMSUN.TTC,SimSun".to_string(),
                    "GULIM.TTC,Gulim".to_string()
                ])
            );
            let (_, res) =
                reg_value(RegFileVersion::Win2K)(r#""C:\\users\\goto-bus-stop\\Temp""#).unwrap();
            assert_eq!(
                res,
                RegValue::String(r"C:\users\goto-bus-stop\Temp".to_string()),
                "unescape values"
            );
            let (_, res) = reg_value(RegFileVersion::Win2K)("-").unwrap();
            assert_eq!(res, RegValue::Deletion, "deleted values");
        }

        #[test]
        fn reg_value_line_test() {
            let (_, res) =
                reg_value_line(RegFileVersion::Win2K)("\"Spec Default\"=dword:00000000\r\n")
                    .unwrap();
            assert_eq!(res, ("Spec Default".to_string(), RegValue::Dword(0)));
            let (_, res) =
                reg_value_line(RegFileVersion::Win2K)("\"Spectate IP\"=\"192.168.178.116\"\r\n")
                    .unwrap();
            assert_eq!(
                res,
                (
                    "Spectate IP".to_string(),
                    RegValue::String("192.168.178.116".to_string())
                )
            );
            let (_, res) = reg_value_line(RegFileVersion::Win2K)("@=dword:00000000\r\n").unwrap();
            assert_eq!(res, ("@".to_string(), RegValue::Dword(0)));
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
