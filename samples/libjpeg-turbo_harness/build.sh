#!/usr/bin/env bash

set -Eeuxo pipefail

mkdir build
cd build

CC=gclang CXX=gclang++ cmake -G"Unix Makefiles" ..
# autoreconf -fiv
# ./configure
make -j $(nproc)

gclang++ -O3 -g -Wextra -Wall -Wfloat-equal -Wundef -Wshadow -Wpointer-arith -Wcast-align \
    -Wstrict-prototypes -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return \
    -static -std=c++11 ../../libjpeg-turbo_harness/libjpeg_turbo_fuzzer.cc -I . -I .. \
    ./libjpeg.a ./libturbojpeg.a ../../libjpeg-turbo_harness/harness.cc -o ../libjpeg_turbo_fuzzer

cd ..
get-bc libjpeg_turbo_fuzzer
