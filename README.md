# dotreg
Parse and stringify Windows registry files (`.reg`).

This crate deals with the text files used by regedit, not the binary registry hive format used by Windows internally.

## Installation
```toml
[dependencies]
dotreg = { git = "https://github.com/goto-bus-stop/dotreg" }
```

## Goals
This should become a part of a crate that does cross-platform Windows registry reads and writes. On windows, it can use the windows `Reg*` APIs. Elsewhere, it can serialize the updates and do `wine reg.exe import tempfile.reg`.

## License
[GPL-3.0](./LICENSE.md)
