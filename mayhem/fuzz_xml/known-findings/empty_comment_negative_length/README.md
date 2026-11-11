# sxmlc `_parse_special_tag`: negative length into `malloc`

`sxmlc.c:1083` allocates `len - tag->len_start - tag->len_end + 1` bytes for a comment/CDATA/DOCTYPE
body. For `<!-->` the start (`<!--`) and end (`-->`) markers overlap, so `len` (5) is smaller than
`len_start + len_end` (7): the size is `-1`, which reaches `malloc` as `SIZE_MAX` (ASan:
`requested allocation size 0xffffffffffffffff`), and the following `sx_strncpy`/store would use a
negative length. Reached by every parse entry point (MRA/MGL files are parsed with this library).

Reproduce: `/mayhem/fuzz_xml -runs=1 repro.xml`.

Fix: after matching both markers, return `TAG_PARTIAL`/`TAG_NONE` when `len < tag->len_start + tag->len_end`.
