//! Library for reading and writing Windows Registry files.

#![deny(future_incompatible)]
#![deny(nonstandard_style)]
#![deny(rust_2018_idioms)]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(unused)]
#![allow(clippy::write_with_newline)]

mod parse;
mod stringify;

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
    /// This value is being deleted.
    Delete,
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
    #[inline]
    pub fn new(name: String) -> RegKey {
        RegKey {
            name,
            values: Default::default(),
        }
    }

    /// Create a symbolic link to some other key.
    #[inline]
    pub fn new_link(name: String, target: &str) -> RegKey {
        let mut key = RegKey::new(name);
        key.set_link_target(target);
        key
    }

    /// Get the root value (@) of this key.
    #[inline]
    pub fn get_root_value(&self) -> Option<&RegValue> {
        self.get_value("@")
    }

    /// Get a value from this key.
    #[inline]
    pub fn get_value(&self, name: &str) -> Option<&RegValue> {
        self.values.get(name)
    }

    #[inline]
    pub fn set_root_value(&mut self, value: RegValue) {
        self.set_value("@", value);
    }

    #[inline]
    pub fn set_value(&mut self, name: &str, value: RegValue) {
        self.values.insert(name.to_string(), value);
    }

    #[inline]
    pub fn delete_value(&mut self, name: &str) {
        self.set_value(name, RegValue::Delete);
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

    #[inline]
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

/// Errors that may occur during parsing.
#[derive(Debug)]
pub enum ParseRegFileError {
    /// An error occurred while reading data.
    IoError(std::io::Error),
    /// Tried to read a string but it was not in the expected encoding (usually UTF-16).
    EncodingError,
    ParseError,
    /// The string was not fully parsed.
    TrailingData(String, RegFile),
}

#[derive(Debug, Clone)]
pub enum RegKeyMod {
    Update(RegKey),
    Delete,
}

/// A registry file containing registry keys.
#[derive(Debug, Clone)]
pub struct RegFile {
    /// The version of the file.
    version: RegFileVersion,
    /// The keys in this file.
    keys: HashMap<String, RegKeyMod>,
}

impl Default for RegFile {
    fn default() -> Self {
        Self {
            version: RegFileVersion::Win2K,
            keys: Default::default(),
        }
    }
}

impl RegFile {
    /// Get the file format version.
    pub fn version(&self) -> RegFileVersion {
        self.version
    }

    /// Iterate over all registry keys.
    pub fn keys(&self) -> impl Iterator<Item = &RegKeyMod> {
        self.keys.values()
    }

    /// Iterate mutably over all registry keys.
    pub fn keys_mut(&mut self) -> impl Iterator<Item = &mut RegKeyMod> {
        self.keys.values_mut()
    }

    /// Add a registry key to this file.
    pub fn add(&mut self, key: RegKey) {
        self.keys.insert(key.name.clone(), RegKeyMod::Update(key));
    }

    /// Delete a registry key.
    pub fn delete(&mut self, name: &str) {
        self.keys.insert(name.to_string(), RegKeyMod::Delete);
    }

    /// Create a registry key in this file and return it.
    pub fn create_key(&mut self, name: &str) -> &mut RegKey {
        let key = RegKey::new(name.to_string());
        self.add(key);
        self.get_key_mut(name).unwrap()
    }

    /// Get a registry key by name.
    pub fn get_key(&self, name: &str) -> Option<&RegKey> {
        self.keys.get(name).and_then(|key_mod| {
            if let RegKeyMod::Update(ref key) = key_mod {
                Some(key)
            } else {
                None
            }
        })
    }

    /// Mutably get a registry key by name.
    pub fn get_key_mut(&mut self, name: &str) -> Option<&mut RegKey> {
        self.keys.get_mut(name).and_then(|key_mod| {
            if let RegKeyMod::Update(key) = key_mod {
                Some(key)
            } else {
                None
            }
        })
    }

    /// Parse a registry file from a UTF-8 string.
    pub fn parse(s: &str) -> Result<Self, ParseRegFileError> {
        let (remaining, regfile) = parse::reg_file(s).map_err(|_| ParseRegFileError::ParseError)?;
        if !remaining.is_empty() {
            // don't really wanna do the to_string() here but dotreg::read needs to be able to
            // return this while dropping the &str local.
            Err(ParseRegFileError::TrailingData(
                remaining.to_string(),
                regfile,
            ))
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

#[derive(Debug, Default, Clone)]
pub struct RegFileBuilder {
    inner: RegFile,
}
impl RegFileBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn version(mut self, version: RegFileVersion) -> Self {
        self.inner.version = version;
        self
    }

    pub fn update_key(mut self, key: RegKey) -> Self {
        self.inner.add(key);
        self
    }

    pub fn delete_key(mut self, path: &str) -> Self {
        self.inner.delete(path);
        self
    }

    pub fn build(self) -> RegFile {
        self.inner
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

    RegFile::parse(&s)
}

const HEADER_WIN95: &str = "REGEDIT4\r\n";
const HEADER_WIN2K: &str = "Windows Registry Editor Version 5.00\r\n";
const HEADER_WINE2: &str = "WINE REGISTRY Version 2\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder() {
        RegFileBuilder::default().build().to_string();
    }
}
