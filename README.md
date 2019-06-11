# dotreg

Parse and stringify Windows registry files (`.reg`).

This crate deals with the text files used by regedit, not the binary registry hive format used by Windows internally.

## Goals

This should become a part of a crate that does cross-platform Windows registry reads and writes. On windows, it can use the windows `Reg*` APIs. Elsewhere, it can serialize the updates and put do `wine reg.exe import tempfile.reg`.

I'd like to do the updates directly to Wine's registry files so it doesn't need a subprocess, so I'm aiming to also support Wine's file format here. It's quite likely that the direct updates won't work out though.

## License

[GPL-3.0](./LICENSE.md)
