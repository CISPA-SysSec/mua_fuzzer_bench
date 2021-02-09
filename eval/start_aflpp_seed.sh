#!/usr/bin/env bash

_term() { 
  echo "Caught SIGINT signala!" 
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

export LD_LIBRARY_PATH=/home/eval/lib/

afl-clang-lto++ /home/eval/lib/libdynamiclibrary.so $1 $2

[[ -d output ]] && rm -rf output
mkdir output

shift
shift

SEEDS="$1"

shift

AFL_ARGS="$1"

shift

export AFL_NO_AFFINITY=1
afl-fuzz $AFL_ARGS -i $SEEDS -o ../output -- ./a.out $@ &
child=$! 

echo "setup done"

wait "$child"
echo "fuzzing done"
