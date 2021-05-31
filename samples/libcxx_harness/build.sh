#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/llvm/llvm-project/blob/d28af7c654d8db0b68c175db5ce212d74fb5e9bc/libcxx/utils/ci/oss-fuzz.sh

mkdir -p $OUT
mkdir -p $WORK

if [[ ${SANITIZER} = *undefined* ]]; then
  CXXFLAGS="${CXXFLAGS} -fsanitize=unsigned-integer-overflow -fsanitize-trap=unsigned-integer-overflow"
fi

for test in libcxx/test/libcxx/fuzzing/*.pass.cpp; do
    exe="$(basename ${test})"
    exe="${exe%.pass.cpp}"
    ${CXX} ${CXXFLAGS} \
        -std=c++14 \
        -DLIBCPP_OSS_FUZZ \
        -D_LIBCPP_HAS_NO_VENDOR_AVAILABILITY_ANNOTATIONS \
        -nostdinc++ -cxx-isystem libcxx/include \
        -lpthread -ldl \
        -o "${OUT}/${exe}" \
        ${test} \
        ${LIB_FUZZING_ENGINE}
done

ls -la $OUT
ls -la $WORK
