#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/google/oss-fuzz/blob/c447cfedf46682dbabc05668e446419d47e22964/projects/re2/build.sh

# First, build RE2.
# N.B., we don't follow the standard incantation for building RE2
# (i.e., `make && make test && make install && make testinstall`),
# because some of the targets doesn't use $CXXFLAGS properly, which
# causes compilation to fail. The obj/libre2.a target is all we
# really need for our fuzzer, so that's all we build. Hopefully
# this won't cause the fuzzer to fail erroneously due to not running
# upstream's tests first to be sure things compiled correctly.
CXXFLAGS="$CXXFLAGS -g -O2"
make clean
make -j obj/libre2.a

cp obj/libre2.a re2_fuzzer.a

# Second, build the fuzzer (distributed with RE2).
LIB_FUZZING_ENGINE="../re2_harness/harness.cc"
$CXX $CXXFLAGS -std=c++11 -static -c -I. \
    -o re2_fuzzer.o \
    re2/fuzzing/re2_fuzzer.cc \
    re2_fuzzer.a

llvm-ar r re2_fuzzer.a re2_fuzzer.o
get-bc -b re2_fuzzer.a
mv re2_fuzzer.a.bc re2_fuzzer.bc

LIB_FUZZING_ENGINE="../re2_harness/harness.cc"
$CXX $CXXFLAGS -std=c++11 \
    $LIB_FUZZING_ENGINE \
    re2_fuzzer.bc \
    -lpthread \
    -o re2_fuzzer

