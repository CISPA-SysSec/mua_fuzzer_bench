#!/usr/bin/env bash

set -Eeuxo pipefail

mkdir -p $OUT
mkdir -p $WORK

meson fuzzbuild --default-library=static -Dexperimental_api=true

ninja -v -Cfuzzbuild test/fuzzing/hb-subset-fuzzer # {shape,draw,subset,set}

cp fuzzbuild/test/fuzzing/hb-subset-fuzzer hb-subset-fuzzer

get-bc hb-subset-fuzzer

# RUN gclang++ -static -Ifuzzbuild/src/ -Isrc/ fuzzbuild/test/fuzzing/5325d79\@\@hb-subset-fuzzer\@exe/.hb-subset-fuzzer.cc.o.bc fuzzbuild/test/fuzzing/5325d79\@\@hb-subset-fuzzer\@exe/.main.cc.o.bc fuzzbuild/src/libharfbuzz-subset.a -lpthread
# WORKDIR /home/mutator/samples/harfbuzz/fuzzbuild/test/fuzzing
# RUN cp -r *@@hb-subset-fuzzer@exe hb-subset-fuzzer-dir
