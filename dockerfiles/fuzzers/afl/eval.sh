#!/usr/bin/env bash

set -Euxo pipefail

echo "workdir: $(pwd)"

export LD_LIBRARY_PATH=/home/user/lib/

if [[ ! -z "${MUT_WITH_ASAN:-}" ]]; then
  echo "Activating ASAN"
  export AFL_USE_ASAN=1
fi

if [[ ! -z "${MUT_WITH_MSAN:-}" ]]; then
  echo "Activating MSAN"
  export AFL_USE_MSAN=1
fi

afl-clang-fast++ /home/user/lib/libdynamiclibrary.so /home/user/common/main.cc $1 $2

[[ -d output ]] && rm -rf output
mkdir output

shift
shift

SEEDS="$1"

shift

export TRIGGERED_OUTPUT=""
export TRIGGERED_FILE="$(pwd)/covered"
export AFL_NO_AFFINITY=1

args=(-d -i $SEEDS -o output)

if [[ ! -z ${DICT_PATH:+x} ]]; then
    args+=(-x)
    args+=("${DICT_PATH}")
fi

if [[ ! -z "${MUT_WITH_ASAN:-}" || ! -z "${MUT_WITH_MSAN:-}" ]]; then
    args+=("-t5000")
    args+=("-m")
    args+=("none")
fi

echo "afl-fuzz ${args[@]} -- ./a.out $@ @@"
exec afl-fuzz ${args[@]} -- ./a.out $@ @@

