#!/usr/bin/env bash

_term() { 
  echo "Caught SIGINT signal!"
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

echo "workdir: $(pwd)"

export LD_LIBRARY_PATH=/home/user/lib/


if [[ ! -z "${MUT_WITH_ASAN}" ]]; then
  echo "Activating ASAN"
  export HFUZZ_CC_ASAN=1
fi

if [[ ! -z "${MUT_WITH_MSAN}" ]]; then
  echo "Activating MSAN"
  export HFUZZ_CC_MSAN=1
fi

hfuzz-clang++ /home/user/lib/libdynamiclibrary.so $1 $2

[[ -d output ]] && rm -rf output
mkdir output

shift
shift

SEEDS="$1"

shift

export TRIGGERED_OUTPUT="$@"
export TRIGGERED_FILE="$(pwd)/covered"
export AFL_NO_AFFINITY=1

args=(--input $SEEDS --output output --crashdir crashes -n 1)

if [[ ! -z ${DICT_PATH:+x} ]]; then
    args+=(--dict)
    args+=("${DICT_PATH}")
fi

echo "honggfuzz ${args[@]} -- ./a.out $@"
exec honggfuzz ${args[@]} -- ./a.out $@

