#!/usr/bin/env bash

_term() { 
  echo "Caught SIGINT signal!"
  kill -INT "$child"
}

trap _term SIGINT

set -Euxo pipefail

echo "workdir: $(pwd)"

export LD_LIBRARY_PATH=/home/user/lib/

libfuzzer_arg="-fsanitize=fuzzer"


if [[ ! -z "${MUT_WITH_ASAN}" ]]; then
  echo "Activating ASAN"
  libfuzzer_arg+=",address"
fi

if [[ ! -z "${MUT_WITH_MSAN}" ]]; then
  echo "Activating MSAN"
  libfuzzer_arg+=",memory"
fi

clang++ "${libfuzzer_arg}" /home/user/lib/libdynamiclibrary.so $1 $2 -o ./libfuzz_target

shift
shift

SEEDS="$1"

cp -r "$SEEDS" ./seeds
echo "seeds: ${SEEDS}"

shift

export TRIGGERED_OUTPUT="$@"
export TRIGGERED_FILE="$(pwd)/covered"
export AFL_NO_AFFINITY=1

args=(-fork=1)

if [[ ! -z ${DICT_PATH:+x} ]]; then
    args+=("-dict=${DICT_PATH}")
fi

mkdir artifacts
cd artifacts
exec ../libfuzz_target ../seeds ${args[@]}

