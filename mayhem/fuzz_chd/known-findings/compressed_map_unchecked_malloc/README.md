# libchdr `decompress_v5_map`: attacker-sized `malloc` from the file

`lib/libchdr/libchdr_chd.c:1579` reads `mapbytes` (a 32-bit big-endian value at the start of the
compressed map) from the file and calls `malloc(mapbytes)` before checking it against the file size, so a
small crafted header can request ~4 GiB (libFuzzer: `out-of-memory (malloc(4294967295))`). Other
header-derived sizes behave the same way: the hunk cache `malloc(header.hunkbytes)` (line 1835) and
`map_size_v5()` returns an `int` (`hunkcount * 4` or `* 12`), which overflows for large hunk counts and
reaches `malloc` as a huge `size_t` (ASan: `allocation-size-too-big` at line 1561).

Impact: denial of service on loading a crafted `.chd`.

Reproduce: `/mayhem/fuzz_chd -runs=1 repro.chd` (libFuzzer reports the 2 GiB+ request as out-of-memory). Fix: validate `mapbytes`, `hunkbytes` and the hunk count
against the file size before allocating, and compute the map size in `size_t`.
