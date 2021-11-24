#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

mkdir -p $OUT
mkdir -p $WORK

pushd libevent
# build project
sh autogen.sh
./configure --disable-openssl
make -j$(nproc) clean
make -j$(nproc) all
# make install


get-bc -b ./.libs/libevent.a
get-bc -b ./.libs/libevent_core.a
get-bc -b ./.libs/libevent_pthreads.a
get-bc -b ./.libs/libevent_extra.a

popd

# build fuzzer
for fuzzers in $(find /home/mutator/samples/libevent_harness -name '*_fuzzer.cc'); do
  fuzz_basename=$(basename -s .cc $fuzzers)
  echo ${fuzz_basename}
  pwd
  $CXX $CXXFLAGS -std=c++11 -I. -Ilibevent/include \
      -c $fuzzers \
      -o $OUT/${fuzz_basename}-entry
    get-bc ${OUT}/${fuzz_basename}-entry

    llvm-link \
        libevent/.libs/libevent.a.bc \
        ${OUT}/${fuzz_basename}-entry.bc \
        -o ${OUT}/${fuzz_basename}.bc

    $CXX $CXXFLAGS \
        -std=c++11 \
        $OUT/${fuzz_basename}.bc \
        $LIB_FUZZING_ENGINE \
        -o $OUT/${fuzz_basename}

done

ls -la ${OUT}