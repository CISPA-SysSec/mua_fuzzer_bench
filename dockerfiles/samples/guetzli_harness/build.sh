#!/usr/bin/env bash

set -Eeuxo pipefail

make -j

pwd

get-bc -b ./bin/Release/libguetzli_static.a

$CXX $CXXFLAGS -g \
    -I. \
    -c fuzz_target.cc \
    -o fuzz-target-entry

get-bc -b fuzz-target-entry

llvm-link \
    -o guetzli.bc \
    fuzz-target-entry.bc \
    ./bin/Release/libguetzli_static.a.bc

$CXX $CXXFLAGS -g -O2 \
    -o guetzli-orig \
    guetzli.bc \
    $LIB_FUZZING_ENGINE