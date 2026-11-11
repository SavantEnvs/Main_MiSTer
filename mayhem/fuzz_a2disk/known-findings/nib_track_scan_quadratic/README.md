# `nib_track_to_dsk_track` / `a2_nib_to_dsk`: quadratic scan of a sector-less NIB track

`support/a2/iigs_fmt.cpp` `nib_track_to_dsk_track()` calls `parse_nib_sector()` at every byte offset.
When the track holds no address field, `parse_nib_sector()` walks to the end of the track before
returning 0 and the caller advances by one byte, so a 6656-byte track costs ~22 million steps. A whole
35-track image (`a2_nib_to_dsk`) costs ~775 million: ~14 s under ASan for an all-zero 232960-byte image.

`repro.bin` is operation 7 with an all-zero track (the 2-byte input is zero-padded by the harness):
a slow unit rather than a hang (about 0.4 s under ASan; 35x that through `a2_nib_to_dsk`).

Impact: loading a crafted `.nib` image stalls the MiSTer's UI thread for seconds.

Fix: have `parse_nib_sector()` report "no address field before here" so the caller can stop scanning,
or advance `pos` past the bytes the failed parse already inspected.
