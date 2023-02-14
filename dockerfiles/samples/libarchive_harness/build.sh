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

mkdir -p $OUT
mkdir -p $WORK
mkdir -p $DEPS

# compile libxml2 from source so we can statically link
DEPS=/deps
mkdir ${DEPS}
cd $SRC/libxml2
./autogen.sh \
    --without-debug \
    --without-ftp \
    --without-http \
    --without-legacy \
    --without-python
make -j$(nproc)
make install
cp .libs/libxml2.a ${DEPS}/
cd $SRC/libarchive

sed -i 's/-Wall//g' ./CMakeLists.txt
sed -i 's/-Werror//g' ./CMakeLists.txt

mkdir build2
cd build2
cmake ../
make

get-bc -b ./libarchive/libarchive.a
get-bc -b ${DEPS}/libxml2.a

pwd

ls -la

echo $SRC

find ../../.. -name "archive.h"

$CC $CFLAGS \
    -I${SRC}/libarchive/libarchive \
    -c /home/mutator/samples/libarchive_harness/libarchive_fuzzer.cc \
    -o $OUT/libarchive_fuzzer-entry
get-bc -b $OUT/libarchive_fuzzer-entry

llvm-link \
    ./libarchive/libarchive.a.bc \
    ${DEPS}/libxml2.a.bc \
    $OUT/libarchive_fuzzer-entry.bc \
    -o $OUT/libarchive.bc

# build fuzzer(s)
$CXX $CXXFLAGS \
    $OUT/libarchive.bc \
    $LIB_FUZZING_ENGINE \
    -lcrypto -lacl -llzma -llz4 -lbz2 -lz -ldl \
    -o $OUT/libarchive_fuzzer

# $CXX $CXXFLAGS -I../libarchive \
#     /home/mutator/samples/libarchive_harness/libarchive_fuzzer.cc \
#     $LIB_FUZZING_ENGINE ./libarchive/libarchive.a \
#     -lcrypto -lacl -llzma -llz4 -lbz2 -lz ${DEPS}/libxml2.a \
#     -o $OUT/libarchive_fuzzer