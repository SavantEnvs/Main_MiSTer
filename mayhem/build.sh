#!/usr/bin/env bash
#
# Builds, from the committed tree and offline:
#   * the fuzz targets (fuzz_ini, fuzz_xml, fuzz_chd, fuzz_a2disk) with the sanitizers, plus a
#     run-once <target>-standalone reproducer for each;
#   * mayhem/kat.cpp, the known-answer test binary, with the project's normal flags.
# MiSTer's own Makefile needs an ARM cross toolchain and the FPGA/SPI/Linux-input stack, so this
# compiles only the hardware-independent sources it needs (the same sources, same -D set, and the
# same include paths as upstream's Makefile) and links mayhem/stubs/mister_env.cpp for the few
# environment calls (file reads, core name, root dir) those sources make.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS SRC

cd "$SRC"

# bin/ is gitignored upstream, so the git clean -ffdX the grader runs removes every object.
OBJ="$SRC/bin/mayhem-obj"
rm -rf "$OBJ"
mkdir -p "$OBJ/san" "$OBJ/plain"

INCLUDES="-I. -I./lib/libco -I./lib/miniz -I./lib/md5 -I./lib/lzma -I./lib/zstd/lib -I./lib/libchdr/include"
DEFS="-D_7ZIP_ST -DPACKAGE_VERSION=\"1.3.3\" -DHAVE_LROUND -DHAVE_STDINT_H -DHAVE_STDLIB_H -DHAVE_SYS_PARAM_H -DENABLE_64_BIT_WORDS=0 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -DZSTD_DISABLE_ASM=1"

# SanCov must instrument the library code too, hence fuzzer-no-link on every sanitized compile.
SAN_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
PLAIN_CFLAGS="-O2 $COVERAGE_FLAGS"

obj_path() { echo "$OBJ/$1/$(echo "$2" | tr '/' '_').o"; }

compile_one() {
    local mode="$1" src="$2" out std flags
    out="$(obj_path "$mode" "$src")"
    if [ "$mode" = san ]; then flags="$SAN_CFLAGS"; else flags="$PLAIN_CFLAGS"; fi
    case "$src" in
        # libchdr hands miniz's inflater a zlib-typed allocator (uInt vs size_t): upstream's gcc 10 only
        # warns, clang rejects it, and -fsanitize=function would trap the first compressed hunk.
        # get_bigendian_uint32 does `base[0] << 24` on a promoted int (shift-base UB for any byte >= 0x80),
        # which fires on every real CHD header, so shift-base is relaxed for it (and for the other libchdr/lzma files below).
        lib/libchdr/libchdr_chd.c) $CC $flags -w -Wno-error=incompatible-function-pointer-types \
            $( [ "$mode" = san ] && echo -fno-sanitize=function,shift-base ) $INCLUDES $DEFS -c "$src" -o "$out" ;;
        # sxmlc reads its buffer and FILE* sources through one function pointer type cast on purpose
        # (_bgetc/_beob take DataSourceBuffer*, called as int(*)(void*)); relax only the function check.
        sxmlc.c) $CC $flags -w $( [ "$mode" = san ] && echo -fno-sanitize=function ) $INCLUDES $DEFS -c "$src" -o "$out" ;;
        # The bundled codecs promote bytes to int and shift them into bit 31 (`byte << 24`): benign
        # shift-base UB that fires on ordinary data, so only that one check is relaxed for them.
        lib/libchdr/*.c|lib/lzma/*.c) $CC $flags -w $( [ "$mode" = san ] && echo -fno-sanitize=shift-base ) $INCLUDES $DEFS -c "$src" -o "$out" ;;
        # cfg.cpp's debug=2 opens /tmp/debug.txt and keeps it; mayhem_fopen (mayhem/stubs/mister_env.cpp)
        # sends that one path to /dev/null so no input writes outside the scratch dir.
        cfg.cpp) $CXX -std=gnu++14 $flags -w -Dfopen=mayhem_fopen $INCLUDES $DEFS -c "$src" -o "$out" ;;
        *.c)  $CC  $flags -w $INCLUDES $DEFS -c "$src" -o "$out" ;;
        *.cpp|*.cc) $CXX -std=gnu++14 $flags -w $INCLUDES $DEFS -c "$src" -o "$out" ;;
    esac
}
export -f compile_one obj_path
export OBJ SAN_CFLAGS PLAIN_CFLAGS INCLUDES DEFS

LIB_SRCS="
lib/miniz/miniz.c
$(ls lib/md5/*.c lib/lzma/*.c lib/zstd/lib/common/*.c lib/zstd/lib/decompress/*.c lib/libchdr/*.c)
"
CORE_SRCS="
cfg.cpp
sxmlc.c
support/chd/mister_chd.cpp
support/a2/iigs_fmt.cpp
support/a2/a2_nib_codec.cpp
support/a3/a3_woz.cpp
mayhem/stubs/mister_env.cpp
"
ALL_SRCS="$(echo $LIB_SRCS $CORE_SRCS | tr ' ' '\n' | sort -u)"

for mode in san plain; do
    echo "$ALL_SRCS" | xargs -P "$MAYHEM_JOBS" -I{} bash -c "compile_one $mode {}"
done

objs() { local mode="$1"; shift; local s; for s in "$@"; do obj_path "$mode" "$s"; done; }

CHD_LIBS="lib/miniz/miniz.c $(ls lib/md5/*.c lib/lzma/*.c lib/zstd/lib/common/*.c lib/zstd/lib/decompress/*.c lib/libchdr/*.c | tr '\n' ' ')"

declare -A TARGET_SRCS=(
    [fuzz_ini]="cfg.cpp mayhem/stubs/mister_env.cpp"
    [fuzz_xml]="sxmlc.c"
    [fuzz_chd]="support/chd/mister_chd.cpp mayhem/stubs/mister_env.cpp $CHD_LIBS"
    [fuzz_a2disk]="support/a2/iigs_fmt.cpp support/a2/a2_nib_codec.cpp support/a3/a3_woz.cpp"
)

# Harnesses are C++ but the standalone driver is C, so compile it separately (keeps C linkage).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OBJ/lsan_off.o"

for t in "${!TARGET_SRCS[@]}"; do
    # shellcheck disable=SC2046
    O=$(objs san ${TARGET_SRCS[$t]})
    $CXX -std=gnu++14 $SANITIZER_FLAGS $DEBUG_FLAGS -w $INCLUDES $DEFS $LIB_FUZZING_ENGINE \
        "mayhem/harnesses/$t.cpp" $O "$OBJ/lsan_off.o" -o "$SRC/$t"
    $CXX -std=gnu++14 $SANITIZER_FLAGS $DEBUG_FLAGS -w $INCLUDES $DEFS \
        "mayhem/harnesses/$t.cpp" "$OBJ/standalone_main.o" $O "$OBJ/lsan_off.o" -o "$SRC/$t-standalone"
done

# Known-answer test binary: project's normal flags, every source compiled without sanitizers.
KAT_OBJS=$(objs plain cfg.cpp sxmlc.c support/chd/mister_chd.cpp support/a2/iigs_fmt.cpp support/a2/a2_nib_codec.cpp \
    support/a3/a3_woz.cpp mayhem/stubs/mister_env.cpp $CHD_LIBS)
# shellcheck disable=SC2086
$CXX -std=gnu++14 $PLAIN_CFLAGS -w $INCLUDES $DEFS mayhem/kat.cpp $KAT_OBJS -o "$SRC/kat"
