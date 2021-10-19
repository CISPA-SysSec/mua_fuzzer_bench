#!/usr/bin/env bash

_term() { 
  echo "Caught SIGINT signal!"
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

echo "workdir: $(pwd)"

export LD_LIBRARY_PATH=/home/user/lib/

ls -la /home/user/

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

echo "afl-fuzz ${args[@]} -- ./a.out $@ @@"
exec afl-fuzz ${args[@]} -- ./a.out $@ @@

