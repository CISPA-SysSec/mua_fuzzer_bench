#!/usr/bin/env bash

set -Euxo pipefail

echo "gathering seeds for following progs: $@"

echo "gathering seeds for following progs: $@" >> seed_gathering.log
date '+%Y-%m-%d::%H-%M-%S' >> seed_gathering.log
find tmp/active_seeds/ -type f | cut -d/ -f3 | sort | uniq -c >> seed_gathering.log
echo "" >> seed_gathering.log

rm -r tmp/fuzzed_seeds/

# fuzz for new seeds
MUT_TIMEOUT=$((60*2)) ./eval.py gather_seeds --fuzzers afl aflpp_det aflpp_rec fairfuzz honggfuzz --progs $@ --num-repeats=3 --dest-dir tmp/fuzzed_seeds/

# import new seeds
./eval.py import_seeds tmp/fuzzed_seeds/ >> seed_gathering.log

# check seeds
MUT_TIMEOUT=$((60)) ./eval.py check_seeds --fuzzers afl aflpp_det aflpp_rec fairfuzz honggfuzz --progs $@

echo "after:" >> seed_gathering.log
date '+%Y-%m-%d::%H-%M-%S' >> seed_gathering.log
find tmp/active_seeds/ -type f | cut -d/ -f3 | sort | uniq -c >> seed_gathering.log
echo "===================================" >> seed_gathering.log
