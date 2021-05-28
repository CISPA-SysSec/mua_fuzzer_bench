#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/OSGeo/PROJ/blob/7b407e36e650aeae986218a0e213b2d8248c008d/test/fuzzers/build.sh

mkdir -p $OUT
mkdir -p $WORK

# cat brotli/shared.mk | sed -e "s/-no-canonical-prefixes//" \
# > brotli/shared.mk.temp
# mv brotli/shared.mk.temp brotli/shared.mk

# woff2 uses LFLAGS instead of LDFLAGS.
make clean
make -j$(nproc) CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= all \
  NOISY_LOGGING=

# Build fuzzers
for fuzzer_archive in src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  out_dir=$OUT/$fuzzer_name
  mkdir -p $out_dir
  cp ${fuzzer_archive} $out_dir
  get-bc -b $out_dir/${fuzzer_name}.a
  mv $out_dir/${fuzzer_name}.a.bc $out_dir/${fuzzer_name}.bc
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $out_dir/${fuzzer_name}.bc \
      -o $out_dir/$fuzzer_name
done

ls -la $OUT
ls -la $WORK

