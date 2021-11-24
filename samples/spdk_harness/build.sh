#!/usr/bin/env bash
# Copyright 2021 Google LLC
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

set -euxo pipefail

mkdir -p $OUT
mkdir -p $WORK

# Build spdk
export LDFLAGS="${CFLAGS}"
./scripts/pkgdep.sh
./configure --without-shared --without-isal
make -j$(nproc)

get-bc -b ../spdk/build/lib/libspdk_env_dpdk.a
get-bc -b ../spdk/build/lib/libspdk_json.a
get-bc -b ../spdk/build/lib/libspdk_log.a
get-bc -b ../spdk/build/lib/libspdk_util.a
get-bc -b ../spdk/dpdk/build/lib/librte_eal.a
get-bc -b ../spdk/dpdk/build/lib/librte_mempool.a
get-bc -b ../spdk/dpdk/build/lib/librte_pci.a
get-bc -b ../spdk/dpdk/build/lib/librte_bus_pci.a
get-bc -b ../spdk/dpdk/build/lib/librte_ring.a
get-bc -b ../spdk/dpdk/build/lib/librte_kvargs.a
get-bc -b ../spdk/dpdk/build/lib/librte_telemetry.a

# Build fuzzers
$CXX $CXXFLAGS \
    -I../spdk \
    -I../spdk/include \
    -fPIC \
    -c /home/mutator/samples/spdk_harness/parse_json_fuzzer.cc \
    -o parse_json_fuzzer.o
get-bc -b parse_json_fuzzer.o

llvm-link \
    parse_json_fuzzer.o.bc \
    ../spdk/build/lib/libspdk_env_dpdk.a.bc \
    ../spdk/build/lib/libspdk_json.a.bc \
    ../spdk/build/lib/libspdk_log.a.bc \
    ../spdk/build/lib/libspdk_util.a.bc \
    ../spdk/dpdk/build/lib/librte_eal.a.bc \
    ../spdk/dpdk/build/lib/librte_mempool.a.bc \
    ../spdk/dpdk/build/lib/librte_pci.a.bc \
    ../spdk/dpdk/build/lib/librte_bus_pci.a.bc \
    ../spdk/dpdk/build/lib/librte_ring.a.bc \
    ../spdk/dpdk/build/lib/librte_kvargs.a.bc \
    ../spdk/dpdk/build/lib/librte_telemetry.a.bc \
    -o ${OUT}/spdk.bc

find ../.. -name "*.bc"
find ../.. -name "*.a"

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        ${OUT}/spdk.bc -ldl -lpthread -lnuma -luuid -o $OUT/parse_json_fuzzer

ls -la ${OUT}
ls -la ${WORK}