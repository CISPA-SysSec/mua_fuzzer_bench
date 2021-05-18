#!/usr/bin/env bash

set -Eeuxo pipefail

export CC=gclang CXX=gclang++

autoreconf -fi
./configure --enable-static --disable-shared --disable-libseccomp
make -j V=1 all

gclang -O3 -g -Wextra -Wall -Wfloat-equal -Wundef -Wshadow -Wpointer-arith -Wcast-align \
    -Wstrict-prototypes -Wstrict-overflow=5 -Wwrite-strings -Waggregate-return \
    -static -Isrc/ -DHAVE_INTTYPES_H \
    ../file_harness/harness.c ../file_harness/magic_fuzzer.c -o magic_fuzzer \
    ./src/.libs/libmagic.a -lz

get-bc magic_fuzzer

# mkdir ../file_harness/seeds/
# cp ./tests/*.testfile ../file_harness/seeds/
#
# cp ./magic/magic.mgc ../file_harness/

