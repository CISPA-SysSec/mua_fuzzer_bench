#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# based on:
# https://github.com/google/fuzzbench/blob/d766ea11b944059f1ef626129a2dfb8adccb2986/benchmarks/sqlite3_ossfuzz/build.sh

mkdir build
cd build

export CC=gclang
export CXX=gclang++
export CFLAGS="-g -O3"
export ASAN_OPTIONS=detect_leaks=0

# Limit max length of data blobs and sql queries to prevent irrelevant OOMs.
# Also limit max memory page count to avoid creating large databases.
export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=128000000 \
               -DSQLITE_MAX_SQL_LENGTH=128000000 \
               -DSQLITE_MAX_MEMORY=25000000 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
               -DSQLITE_DEBUG=1 \
               -DSQLITE_MAX_PAGE_COUNT=16384"

../configure
make -j$(nproc)
make sqlite3.c

$CC $CFLAGS -static -I. -c \
    ../test/ossfuzz.c -o ../ossfuzz.o

$CC $CFLAGS -static \
    ../ossfuzz.o ./sqlite3.o ../../sqlite3_harness/harness.c -lpthread -ldl -o ../sqlite3_ossfuzz

cd ..
get-bc sqlite3_ossfuzz

