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
    -o $OUT/ares-parse-reply-entry

get-bc -b $OUT/ares-parse-reply-entry

llvm-link \
    -o $OUT/ares-parse-reply.bc \
    $OUT/ares-parse-reply-entry.bc \
    $OUT/libcares.bc

$CXX $CXXFLAGS \
    -std=c++11 \
    $OUT/ares-parse-reply.bc \
    -o $OUT/ares-parse-reply \
    $LIB_FUZZING_ENGINE

# name
$CC $CFLAGS \
    -Iinclude \
    -Isrc/lib \
    -c $SRC/test/ares-test-fuzz-name.c \
    -o $OUT/ares-name-entry

get-bc -b $OUT/ares-name-entry

llvm-link \
    -o $OUT/ares-name.bc \
    $OUT/ares-name-entry.bc \
    $OUT/libcares.bc

$CXX $CXXFLAGS \
    -std=c++11 \
    $OUT/ares-name.bc \
    -o $OUT/ares-name \
    $LIB_FUZZING_ENGINE
