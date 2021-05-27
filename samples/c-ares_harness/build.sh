#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/google/oss-fuzz/blob/dc4297c38da6bfabd9e6eb92d81a8b58893a42ca/projects/c-ares/build.sh

mkdir -p $OUT
mkdir -p $WORK

# Build the project.
# ./buildconf
autoreconf -fi
./configure --enable-debug
make clean
make -j$(nproc) V=1 all

# use the static archive as mutation base
cp $SRC/src/lib/.libs/libcares.a $OUT/libcares.a

# llvm-ar r $OUT/libcares.a $OUT/libcares.o
get-bc -b $OUT/libcares.a
mv $OUT/libcares.a.bc $OUT/libcares.bc

############
# Build the different entry points

# parse reply
$CC $CFLAGS \
    -Iinclude \
    -Isrc/lib \
    -c $SRC/test/ares-test-fuzz.c \
    -o $OUT/ares-test-fuzz.o

$CXX $CXXFLAGS \
    -std=c++11 \
    $OUT/ares-test-fuzz.o \
    -o $OUT/ares_parse_reply_fuzzer \
    $LIB_FUZZING_ENGINE \
    $OUT/libcares.bc

# name
$CC $CFLAGS \
    -Iinclude \
    -Isrc/lib \
    -c $SRC/test/ares-test-fuzz-name.c \
    -o $OUT/ares-test-fuzz-name.o

$CXX $CXXFLAGS \
    -std=c++11 \
    $OUT/ares-test-fuzz-name.o \
    $LIB_FUZZING_ENGINE \
    -o $OUT/ares_create_query_fuzzer \
    $OUT/libcares.bc

