#!/usr/bin/env bash

set -Eeuxo pipefail

# Increase (from default) the number of allowed open files descriptors,
# this is needed for larger numbers of concurrent runs. Otherwise docker runs out of file descriptors.
ulimit -n 50000

# also set number of available shared memory pages (not portable, set manually)
# echo 134217728 | sudo tee /proc/sys/kernel/shmmni

# Set core pattern. This is needed for afl to be able to detect crashes and hangs (see afl docs).
echo core | sudo tee /proc/sys/kernel/core_pattern

# Set performance governor for all cores, we want to have full performance to evaluate as consistently as possible.
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
# (cd /sys/devices/system/cpu && echo performance | sudo tee cpu*/cpufreq/scaling_governor >/dev/null)

echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
# Disable aslr on host
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
