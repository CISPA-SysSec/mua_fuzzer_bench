#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/google/fuzzbench/blob/d2234a0cfa532058f1a57328dbefab3d24ee5894/benchmarks/bloaty_fuzz_target/build.sh

mkdir -p $OUT
mkdir -p $WORK

cd $WORK
cmake -G Ninja -DBUILD_TESTING=false $SRC
ninja -j$(nproc)
cp fuzz_target $OUT

get-bc $OUT/fuzz_target

ls -la $OUT
ls -la $WORK

