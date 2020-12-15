#!/usr/bin/env bash

_term() { 
  echo "Caught SIGINT signala!" 
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

export AFL_USE_UBSAN=1
export LD_LIBRARY_PATH=/home/eval/lib/

afl-clang-lto++ /home/eval/lib/libdynamiclibrary.so $1 $2

[[ -d output ]] && rm -rf output
mkdir output

shift
shift

SEEDS="$1"

shift

export TRIGGERED_OUTPUT="$@"
export TRIGGERED_FILE="$(pwd)/covered"
export AFL_NO_AFFINITY=1
afl-fuzz -t 4000+ -m none -d -i $SEEDS -o output -- ./a.out $@ &
child=$! 

echo "setup done"

wait "$child"
echo "fuzzing done"
