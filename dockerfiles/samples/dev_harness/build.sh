#!/usr/bin/env bash

set -Eeuxo pipefail

mkdir -p $OUT
mkdir -p $WORK

# Compile a c file to .bc
$CC $CFLAGS \
    -Iinclude \
    -Isrc/lib \
    -c ../dev_harness/test.c \
    -o $OUT/test

get-bc -b $OUT/test

# # To link together multiple .bc files use llvm-link
# llvm-link \
#     -o $OUT/combined.bc \
#     $OUT/first.bc \
#     $OUT/second.bc

# Create the unmutated executable, there can be no main() function yet.
$CXX $CXXFLAGS \
    -std=c++11 \
    $OUT/test.bc \
    -o $OUT/test \
    $LIB_FUZZING_ENGINE
