#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/openthread/openthread/blob/d3464814948a457f33b2df3a02856ab2f3533a19/tests/fuzz/oss-fuzz-build

mkdir -p $OUT
mkdir -p $WORK

(
    mkdir build
    cd build || exit

    cmake -GNinja \
        -DCMAKE_C_FLAGS="${CFLAGS}" \
        -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
        -DOT_BUILD_EXECUTABLES=OFF \
        -DOT_FUZZ_TARGETS=ON \
        -DOT_MTD=OFF \
        -DOT_PLATFORM=external \
        -DOT_RCP=OFF \
        -DOT_BORDER_AGENT=ON \
        -DOT_BORDER_ROUTER=ON \
        -DOT_CHANNEL_MANAGER=ON \
        -DOT_CHANNEL_MONITOR=ON \
        -DOT_CHILD_SUPERVISION=ON \
        -DOT_COAP=ON \
        -DOT_COAPS=ON \
        -DOT_COAP_BLOCK=ON \
        -DOT_COAP_OBSERVE=ON \
        -DOT_COMMISSIONER=ON \
        -DOT_DATASET_UPDATER=ON \
        -DOT_DHCP6_CLIENT=ON \
        -DOT_DHCP6_SERVER=ON \
        -DOT_DNS_CLIENT=ON \
        -DOT_ECDSA=ON \
        -DOT_IP6_FRAGM=ON \
        -DOT_JAM_DETECTION=ON \
        -DOT_JOINER=ON \
        -DOT_LINK_RAW=ON \
        -DOT_LOG_OUTPUT=APP \
        -DOT_MAC_FILTER=ON \
        -DOT_MTD_NETDIAG=ON \
        -DOT_PING_SENDER=ON \
        -DOT_SERVICE=ON \
        -DOT_SLAAC=ON \
        -DOT_SNTP_CLIENT=ON \
        -DOT_SRP_CLIENT=ON \
        -DOT_SRP_SERVER=ON \
        -DOT_THREAD_VERSION=1.2 \
        ..
    ninja
)

find . -name '*-fuzzer' -exec cp -v '{}' "$OUT" ';'

ls -la $OUT
ls -la $WORK

