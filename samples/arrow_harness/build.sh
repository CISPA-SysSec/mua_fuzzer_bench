#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/google/oss-fuzz/blob/dc4297c38da6bfabd9e6eb92d81a8b58893a42ca/projects/c-ares/build.sh

mkdir -p $OUT
mkdir -p $WORK

ARROW=${SRC}/cpp

cd ${WORK}

# The CMake build setup compiles and runs the Thrift compiler, but ASAN
# would report leaks and error out.
export ASAN_OPTIONS="detect_leaks=0"

cmake ${ARROW} -GNinja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DARROW_USE_ASAN=off \
    -DARROW_USE_UBSAN=off \
    -DARROW_FUZZING=on

ls -la $OUT
ls -la $WORK
