#!/usr/bin/env bash

set -Eeuxo pipefail

if [ ! -d tmp/seeds ]; then
    mkdir -p tmp/seeds
    # Get the zip file
    curl https://ruhr-uni-bochum.sciebo.de/s/gZKykTb8OYwFW1B/download > tmp/seeds.zip

    cd tmp/seeds
    unzip ../seeds.zip

    cd ..
fi

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/guetzli $(pwd)/tmp/minimized_seeds/guetzli guetzli

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/libjpeg $(pwd)/tmp/minimized_seeds/libjpeg libjpeg

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/aspell $(pwd)/tmp/minimized_seeds/aspell aspell

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/c-ares-query $(pwd)/tmp/minimized_seeds/c-ares-query cares_name

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/c-ares-parse-reply $(pwd)/tmp/minimized_seeds/c-ares-parse-reply cares_parse_reply

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/woff2_base $(pwd)/tmp/minimized_seeds/woff2_base woff2_base

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/woff2_new $(pwd)/tmp/minimized_seeds/woff2_new woff2_new

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/re2 $(pwd)/tmp/minimized_seeds/re2 re2

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/vorbis $(pwd)/tmp/minimized_seeds/vorbis vorbis

