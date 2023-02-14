#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/xiph/vorbis/blob/84c023699cdf023a32fa4ded32019f194afcdad0/contrib/oss-fuzz/build.sh

pushd $SRC/ogg
./autogen.sh
./configure --prefix="$WORK" --enable-static --disable-shared --disable-crc
make clean
make -j$(nproc)
make install
popd


./autogen.sh
./configure --prefix="$WORK" --enable-static --disable-shared
make clean
make -j$(nproc)
make install

mkdir -p $OUT

$CXX $CXXFLAGS \
    $SRC/contrib/oss-fuzz/decode_fuzzer.cc \
    -o $OUT/decode_fuzzer \
    -L"$WORK/lib" \
    -I"$WORK/include" \
    $LIB_FUZZING_ENGINE \
    -lvorbisfile -lvorbis -logg

get-bc $OUT/decode_fuzzer

