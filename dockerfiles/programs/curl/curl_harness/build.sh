#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/curl/curl-fuzzer/blob/adefca19f09bb05b3434d2eb0ce060045e994c2d/ossfuzz.sh

mkdir -p $OUT
mkdir -p $WORK

./scripts/ossfuzzdeps.sh

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
SCRIPTDIR=${BUILD_ROOT}/scripts

. ${SCRIPTDIR}/fuzz_targets

ZLIBDIR=$SRC/zlib
OPENSSLDIR=$SRC/openssl
NGHTTPDIR=$SRC/nghttp2

echo "CC: $CC"
echo "CXX: $CXX"
echo "LIB_FUZZING_ENGINE: $LIB_FUZZING_ENGINE"
echo "CFLAGS: $CFLAGS"
echo "CXXFLAGS: $CXXFLAGS"
# echo "ARCHITECTURE: $ARCHITECTURE"
echo "FUZZ_TARGETS: $FUZZ_TARGETS"

export MAKEFLAGS+="-j$(nproc)"

# Make an install directory
export INSTALLDIR=$OUT

# Install zlib
${SCRIPTDIR}/handle_x.sh zlib ${ZLIBDIR} ${INSTALLDIR} || exit 1

# turn off openssl to reduce binary size
# # For the memory sanitizer build, turn off OpenSSL as it causes bugs we can't
# # affect (see 16697, 17624)
# if [[ ${SANITIZER} != "memory" ]]
# then
#     # Install openssl
#     export OPENSSLFLAGS="-fno-sanitize=alignment"
#     ${SCRIPTDIR}/handle_x.sh openssl ${OPENSSLDIR} ${INSTALLDIR} || exit 1
# fi

# Install nghttp2
${SCRIPTDIR}/handle_x.sh nghttp2 ${NGHTTPDIR} ${INSTALLDIR} || exit 1

# Compile curl
${SCRIPTDIR}/install_curl.sh $SRC ${INSTALLDIR}

# Build the fuzzers.
${SCRIPTDIR}/compile_fuzzer.sh ${INSTALLDIR}
# make zip

# Copy the fuzzers over.
for TARGET in $FUZZ_TARGETS
do
  # cp -v ${TARGET} ${TARGET}_seed_corpus.zip $OUT/
  cp -v ${TARGET} $OUT/
done

get-bc -b $OUT/lib/libcurl.a

$CXX $CXXFLAGS \
  -DFUZZ_PROTOCOLS_ALL \
  -c curl_fuzzer.cc \
  -o $OUT/curl_fuzzer-entry
get-bc -b $OUT/curl_fuzzer-entry

$CXX $CXXFLAGS \
  -c curl_fuzzer_tlv.cc \
  -o $OUT/curl_fuzzer_tlv
get-bc -b $OUT/curl_fuzzer_tlv

$CXX $CXXFLAGS \
  -c curl_fuzzer_callback.cc \
  -o $OUT/curl_fuzzer_callback
get-bc -b $OUT/curl_fuzzer_callback

llvm-link \
  -o $OUT/curl.bc \
  $OUT/curl_fuzzer-entry.bc \
  $OUT/curl_fuzzer_tlv.bc \
  $OUT/curl_fuzzer_callback.bc \
  $OUT/lib/libcurl.a.bc

$CXX $CXXFLAGS \
  -o $OUT/curl_fuzzer \
  $OUT/curl.bc \
  $LIB_FUZZING_ENGINE \
  -L $OUT/lib/ \
  -lpthread \
  -lidn2 \
  -lz \
  -lnghttp2


# Copy dictionary and options file to $OUT.
cp -v ossconfig/*.dict ossconfig/*.options $OUT/

ls -la $OUT
ls -la $WORK

