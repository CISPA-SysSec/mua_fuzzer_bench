#!/usr/bin/env bash

_term() { 
  echo "Caught SIGINT signala!" 
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

rm -rf input
mkdir input
echo "a" > input/0

rm -rf output
mkdir output

afl-clang-lto $1

shift

export AFL_NO_AFFINITY=1
afl-fuzz -d -i input -o output -- ./a.out $@ &

child=$! 
wait "$child"
echo "done"