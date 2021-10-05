#!/usr/bin/env bash

_term() {
  echo "Caught SIGINT signal!"
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

echo "workdir: $(pwd)"

export AFL_USE_MSAN=1
export LD_LIBRARY_PATH=/home/user/lib/

export AFL_LLVM_USE_TRACE_PC=1
export AFL_LLVM_DICT2FILE="$(pwd)/afl++.dict"

afl-c++ -o put -v /home/user/lib/libdynamiclibrary.so $1 $2

[[ -d output ]] && rm -rf output
mkdir output

shift
shift

SEEDS="$1"

shift

export TRIGGERED_OUTPUT="$@"
export TRIGGERED_FILE="$(pwd)/covered"
export AFL_NO_AFFINITY=1

args=(-d -i $SEEDS -o output)

if [[ ! -z ${DICT_PATH:+x} ]]; then
    args+=(-x)
    args+=("${DICT_PATH}")
fi

exec afl-fuzz -t200 ${args[@]} -m none -x "./afl++.dict" -l 2 -- ./put $@
