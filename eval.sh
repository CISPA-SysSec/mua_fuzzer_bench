#!/usr/bin/env bash

_term() { 
  echo "Caught SIGINT signal!"
  kill -INT "$child"
}

trap _term SIGINT

set -Eeuxo pipefail

# set the number of allowed files, this is needed for larger numbers of
# concurrent runs
ulimit -n 50000
# also set number of available shared memory
echo 134217728 | sudo tee /proc/sys/kernel/shmmni
# also set core pattern
echo core | sudo tee /proc/sys/kernel/core_pattern
# we want perf
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
# disable aslr on host
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

(cd /sys/devices/system/cpu && echo performance | sudo tee cpu*/cpufreq/scaling_governor >/dev/null)

# build the mutator image (to be sure this could also rebuild the image)
echo yes | ./mutator-docker-wrapper.py -s
echo yes | ./mutator-docker-wrapper.py -b

rm -rf /dev/shm/mutator/
sudo rm -rf ./tmp/*

docker create -ti --name dummy mutator_mutator bash
sudo rm -rf tmp/samples/ && docker cp dummy:/home/mutator/samples/ tmp/ && \
    docker cp dummy:/home/mutator/build/install/LLVM_Mutation_Tool/lib/ tmp/lib/
docker rm -f dummy

exec ./eval.py "eval" "$@"
