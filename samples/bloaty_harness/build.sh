#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/google/fuzzbench/blob/d2234a0cfa532058f1a57328dbefab3d24ee5894/benchmarks/bloaty_fuzz_target/build.sh

mkdir -p $OUT
mkdir -p $WORK

cd $WORK
cmake -G Ninja -DBUILD_TESTING=false $SRC
ninja -j$(nproc)

$CXX $CXXFLAGS \
    -std=c++17 \
    -I../src/ \
    -I../third_party/abseil-cpp \
    -I../third_party/capstone/include \
    -I../third_party/protobuf/src/ \
    -Isrc/ \
    -c ../tests/fuzz_target.cc \
    -o fuzz_target-entry

get-bc -b fuzz_target-entry
get-bc -b liblibbloaty.a

llvm-link \
    -o bloaty.bc \
    .fuzz_target-entry.bc \
    liblibbloaty.a.bc

$CXX $CXXFLAGS -g -O2 \
    -o bloaty-orig \
    bloaty.bc \
    $LIB_FUZZING_ENGINE \
    -L third_party/protobuf/cmake/ \
    -L third_party/re2/ \
    -L third_party/capstone/ \
    -l protobuf \
    -l re2 \
    -l capstone \
    -l pthread \
    -l z

ls -la $OUT
ls -la $WORK

