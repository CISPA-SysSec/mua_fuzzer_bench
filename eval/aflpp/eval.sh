#!/usr/bin/env bash

_term() {
  echo "Caught SIGINT signal!"
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

echo "workdir: $(pwd)"

export LD_LIBRARY_PATH=/home/user/lib/

export AFL_LLVM_USE_TRACE_PC=1
export AFL_LLVM_DICT2FILE="$(pwd)/afl++.dict"

if [[ ! -z "${MUT_WITH_ASAN:-}" ]]; then
  echo "Activating ASAN"
  export AFL_USE_ASAN=1
fi

if [[ ! -z "${MUT_WITH_MSAN:-}" ]]; then
  echo "Activating MSAN"
  export AFL_USE_MSAN=1
fi

afl-c++ -o put -v /home/user/lib/libdynamiclibrary.so /home/user/aflpp_main.cc $1 $2

AFL_LLVM_CMPLOG=1 afl-c++ -o cmplog -v /home/user/lib/libdynamiclibrary.so /home/user/aflpp_main.cc $1 $2

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

echo "afl-fuzz ${args[@]} -- ./put $@"
exec afl-fuzz ${args[@]} -c ./cmplog -m none -x "./afl++.dict" -l 2 -- ./put $@

