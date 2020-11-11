#!/usr/bin/env bash

_term() { 
  echo "Caught SIGINT signala!" 
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

pwd

afl-clang-fast++ $1 $2

[[ -d output ]] && rm -rf output
mkdir output

shift
shift

SEEDS="$1"

shift

export AFL_NO_AFFINITY=1
afl-fuzz -d -i $SEEDS -o output -- ./a.out $@ &

child=$! 
wait "$child"
echo "done"
