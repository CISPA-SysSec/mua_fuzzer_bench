#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/google/oss-fuzz/blob/dc4297c38da6bfabd9e6eb92d81a8b58893a42ca/projects/freetype2/build.sh

mkdir -p $OUT
mkdir -p $WORK

# Tell CMake what fuzzing engine to link:
export CMAKE_FUZZING_ENGINE="$LIB_FUZZING_ENGINE"

bash "fuzzing/scripts/build-fuzzers.sh"
bash "fuzzing/scripts/prepare-oss-fuzz.sh"

# Rename the `legacy' target to `ftfuzzer' for historical reasons:
for f in "${OUT}/legacy"*; do
    mv "${f}" "${f/legacy/ftfuzzer}"
done

get-bc $OUT/ftfuzzer

ls -la $WORK
ls -la $OUT

# # Build the project.
# # ./buildconf
# autoreconf -fi
# ./configure --enable-debug
# make clean
# make -j$(nproc) V=1 all
#
# # use the static archive as mutation base
# cp $SRC/src/lib/.libs/libcares.a $OUT/libcares.a
#
# # llvm-ar r $OUT/libcares.a $OUT/libcares.o
# get-bc -b $OUT/libcares.a
# mv $OUT/libcares.a.bc $OUT/libcares.bc
#
# ############
# # Build the different entry points
#
# # parse reply
# $CC $CFLAGS \
#     -Iinclude \
#     -Isrc/lib \
#     -c $SRC/test/ares-test-fuzz.c \
#     -o $OUT/ares-test-fuzz.o
#
# $CXX $CXXFLAGS \
#     -std=c++11 \
#     $OUT/ares-test-fuzz.o \
#     -o $OUT/ares_parse_reply_fuzzer \
#     $LIB_FUZZING_ENGINE \
#     $OUT/libcares.bc
#
# # name
# $CC $CFLAGS \
#     -Iinclude \
#     -Isrc/lib \
#     -c $SRC/test/ares-test-fuzz-name.c \
#     -o $OUT/ares-test-fuzz-name.o
#
# $CXX $CXXFLAGS \
#     -std=c++11 \
#     $OUT/ares-test-fuzz-name.o \
#     $LIB_FUZZING_ENGINE \
#     -o $OUT/ares_create_query_fuzzer \
#     $OUT/libcares.bc

