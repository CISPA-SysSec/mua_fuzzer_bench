#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/google/oss-fuzz/blob/dc4297c38da6bfabd9e6eb92d81a8b58893a42ca/projects/c-ares/build.sh

mkdir -p $OUT
mkdir -p $WORK

make mjs

pushd ${WORK}

ls -la
${CC} ${CFLAGS} \
    -std=c99 \
    -Wall \
    -Wextra \
    -pedantic \
    -g \
    -I../. \
    -I../src \
    -I../src/frozen \
    -DMJS_EXPOSE_PRIVATE \
    -DCS_ENABLE_STDIO \
    -DMJS_ENABLE_DEBUG \
    -DCS_MMAP \
    -DMJS_MODULE_LINES \
    -c ../mjs.c \
    -o mjs
get-bc -b mjs

$CC $CFLAGS \
    -I../src \
    -c ../../mjs_harness/fuzzer_entry.c \
    -o fuzzer_entry
get-bc -b fuzzer_entry

ls -la

llvm-link \
    mjs.bc \
    fuzzer_entry.bc \
    -o $OUT/mjs.bc

$CC $CFLAGS \
    -ldl \
    $OUT/mjs.bc \
    $LIB_FUZZING_ENGINE \
    -o ${OUT}/mjs_fuzzer
