# `mister_load_chd`: stack buffer overflow in the track-metadata `sscanf`

`support/chd/mister_chd.cpp` parses each CD track's metadata string (up to 512 bytes, taken straight
from the CHD file) with `sscanf(tmp, CDROM_TRACK_METADATA2_FORMAT, ..., track_type, subtype, ..., pgtype, pgsub, ...)`
into `char track_type[64], subtype[32], pgtype[32], pgsub[32]`. The libchdr formats are unbounded
`%s`, so a metadata string with a long word writes past the 32/64-byte stack arrays (ASan:
`stack-buffer-overflow` in `scanf_common`, called from `mister_chd.cpp:67`). Same for the v1 format at line 71.

Impact: loading a crafted `.chd` disc image from the SD card corrupts the stack of the MiSTer binary.

Reproduce: `/mayhem/fuzz_chd-standalone repro.chd` (or `/mayhem/fuzz_chd -runs=1 repro.chd`).

Fix: bound the conversions to the array sizes, e.g. `%63s`/`%31s`, in a local copy of the format strings.
