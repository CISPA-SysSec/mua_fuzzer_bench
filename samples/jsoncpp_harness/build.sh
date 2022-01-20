#!/usr/bin/env bash
# Copyright 2018 Google Inc.
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

# adapted from: https://github.com/google/fuzzbench/blob/e40c64c9c2f8b78fa521554f6270f16e5587207d/benchmarks/jsoncpp_jsoncpp_fuzzer/build.sh

set -Eeuxo pipefail

mkdir -p $OUT
mkdir -p $WORK

cd $WORK
# mkdir -p build
# cd build

# get jsoncpp lib as bc file
cmake -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF -DJSONCPP_WITH_TESTS=OFF \
      -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles" ..
make
get-bc -b lib/libjsoncpp.a

# compile fuzzer part as bc file
$CXX $CXXFLAGS \
    -I../include \
    -c ../src/test_lib_json/fuzz.cpp \
    -o jsoncpp_fuzzer-entry
get-bc -b jsoncpp_fuzzer-entry

# combine for unified bc file
llvm-link \
    -o $OUT/jsoncpp.bc \
    jsoncpp_fuzzer-entry.bc \
    lib/libjsoncpp.a.bc

# compile orig version
$CXX $CXXFLAGS \
    -o $OUT/jsoncpp-orig \
    $OUT/jsoncpp.bc \
    $LIB_FUZZING_ENGINE
