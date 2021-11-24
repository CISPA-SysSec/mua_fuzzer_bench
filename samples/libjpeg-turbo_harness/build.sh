#!/usr/bin/env bash

set -Eeuxo pipefail

mkdir -p $OUT
mkdir -p $WORK

cd $WORK

# CC=gclang CXX=gclang++ cmake -G"Unix Makefiles" ..
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DWITH_SIMD=0 -DENABLE_STATIC=1 -DENABLE_SHARED=0 \
	-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
	-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG"

# autoreconf -fiv
# ./configure
make -j $(nproc)

get-bc -b ./libjpeg.a
get-bc -b ./libturbojpeg.a

$CXX $CXXFLAGS -g -static -std=c++11 \
    -c ../../libjpeg-turbo_harness/libjpeg_turbo_fuzzer.cc \
    -I . -I .. \
    -o $OUT/libjpeg_turbo_fuzzer-entry

get-bc -b $OUT/libjpeg_turbo_fuzzer-entry

llvm-link \
    $OUT/libjpeg_turbo_fuzzer-entry.bc \
    ./libturbojpeg.a.bc \
    -o $OUT/libjpeg.bc

    # ./libjpeg.a.bc \

$CXX $CXXFLAGS \
    -g -static -std=c++11 \
    $OUT/libjpeg.bc \
    $LIB_FUZZING_ENGINE \
    -o $OUT/libjpeg


# $CXX $CXXFLAGS -O3 -g -Wextra -Wall -Wfloat-equal -Wundef -Wshadow -Wpointer-arith -Wcast-align \
#     -Wstrict-prototypes -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return \
#     -static -std=c++11 ../../libjpeg-turbo_harness/libjpeg_turbo_fuzzer.cc -I . -I .. \
#     ./libjpeg.a ./libturbojpeg.a ../../libjpeg-turbo_harness/harness.cc -o ../libjpeg_turbo_fuzzer

# cd ..
# get-bc libjpeg_turbo_fuzzer
