use crate::{
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

/// Read a string surrounded by double quotes.
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

/// Read a value, like "dword:00000001"
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
