#!/usr/bin/env bash

set -Eeuxo pipefail

# Increase (from default) the number of allowed open files descriptors,
# this is needed for larger numbers of concurrent runs.
# Otherwise, docker runs out of file descriptors.
ulimit -n 50000
ulimit -Sn 50000

# Set core pattern. This is needed for afl to be able
# to detect crashes and hangs (see afl docs).
echo core | sudo tee /proc/sys/kernel/core_pattern

# Set performance governor for all cores, we want to have full performance
# to evaluate as consistently as possible.
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable aslr on host, makes fuzzing bit more consistent.
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
