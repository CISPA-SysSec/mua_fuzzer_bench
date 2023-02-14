#!/usr/bin/env bash

_term() { 
  echo "Caught SIGINT signal!"
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

echo "workdir: $(pwd)"

export LD_LIBRARY_PATH=/home/user/lib/

clang++ -fsanitize=fuzzer /home/user/lib/libdynamiclibrary.so $1 $2 -o ./libfuzz_target

shift
shift

SEEDS_IN="$1"
SEEDS_OUT="$2"

shift
shift

exec ./libfuzz_target -merge=1 "${SEEDS_OUT}" "${SEEDS_IN}"
