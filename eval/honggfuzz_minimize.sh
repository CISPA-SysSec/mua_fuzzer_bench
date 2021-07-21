#!/usr/bin/env bash

_term() {
  echo "Caught SIGINT signal!"
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

echo "workdir: $(pwd)"

export LD_LIBRARY_PATH=/home/user/lib/

hfuzz-clang++ -o put -v /home/user/lib/libdynamiclibrary.so $1 $2

[[ -d output ]] && rm -rf output
mkdir output

shift
shift

SEEDS_IN="$1"
SEEDS_OUT="$2"

shift
shift

export AFL_NO_AFFINITY=1

echo "honggfuzz -i "$SEEDS_IN" --output "$SEEDS_OUT" -M -- ./put $@"
exec honggfuzz -i "$SEEDS_IN" --output "$SEEDS_OUT" -M -- ./put $@
