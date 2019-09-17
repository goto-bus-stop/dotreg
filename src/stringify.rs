use super::{RegFile, RegFileVersion, RegKey, RegKeyMod, RegValue, HEADER_WIN2K, HEADER_WIN95};
use std::fmt::Write;

fn header(version: RegFileVersion) -> &'static str {
    use RegFileVersion::*;
    match version {
        Win95 => HEADER_WIN95,
        Win2K => HEADER_WIN2K,
    }
}

fn reg_key_header(name: &str, output: &mut String) {
    write!(output, "[{}]\r\n", name).unwrap();
}

fn reg_key_delete(name: &str, output: &mut String) {
    write!(output, "[-{}]\r\n", name).unwrap();
}

fn quoted_string(s: &str, output: &mut String) {
    output.push('"');
    for c in s.chars() {
        match c {
            '\\' => output.push_str(r"\\"),
            '\t' => output.push_str(r"\t"),
            '\r' => output.push_str(r"\r"),
            '\n' => output.push_str(r"\n"),
            '"' => output.push_str(r#"\""#),
            c => output.push(c),
        }
    }
    output.push('"');
}

fn reg_value(value: &RegValue, output: &mut String) {
    match value {
        RegValue::Dword(n) => write!(output, "dword:{:08x}", n).unwrap(),
        RegValue::String(s) => quoted_string(s, output),
        RegValue::Binary(v) => {
            output.push_str("hex:");
            for byte in v {
                write!(output, "{:02x},", byte).unwrap();
            }
            if v.len() > 0 {
                output.pop();
            }
        }
        RegValue::Link(target) => {
            output.push_str("hex(6):");
            for byte in target.as_bytes() {
                write!(output, "{:02x},", byte).unwrap();
            }
            if target.len() > 0 {
                output.pop();
            }
        }
        _ => unimplemented!(),
    };
}

fn reg_value_line(name: &str, value: &RegValue, output: &mut String) {
    if name == "@" {
        output.push('@');
    } else {
        quoted_string(name, output);
    }
    output.push('=');
    reg_value(value, output);
}

fn reg_values<'a>(values: impl IntoIterator<Item = (&'a str, &'a RegValue)>, output: &mut String) {
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

    for (name, key_mod) in file.keys.iter() {
        match key_mod {
            RegKeyMod::Delete => reg_key_delete(name, output),
            RegKeyMod::Update(key) => reg_key(key, output),
        }
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
        reg_value(
            &RegValue::String("esc\r\na\"pe\\t\this".to_string()),
            &mut result,
        );
        assert_eq!(result, r#""esc\r\na\"pe\\t\this""#);
        result.clear();
        reg_value(&RegValue::Binary(vec![0, 1, 2, 3]), &mut result);
        assert_eq!(result, "hex:00,01,02,03");
        result.clear();
    }
}
