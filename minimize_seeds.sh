#!/usr/bin/env bash

set -Eeuxo pipefail

if [ ! -d tmp/seeds ]; then
    mkdir -p tmp/seeds
    # Get the zip file
    curl https://ruhr-uni-bochum.sciebo.de/s/gZKykTb8OYwFW1B/download > tmp/seeds.zip

    pushd tmp/seeds
    unzip ../seeds.zip

    popd
fi

mkdir -p $(pwd)/tmp/minimized_seeds

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/c-ares-query $(pwd)/tmp/minimized_seeds/c-ares-query cares_name 2>&1 | tee $(pwd)/tmp/minimized_seeds/cares_name.log

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/c-ares-parse-reply $(pwd)/tmp/minimized_seeds/c-ares-parse-reply cares_parse_reply 2>&1 | tee $(pwd)/tmp/minimized_seeds/cares_parse_reply.log

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/guetzli $(pwd)/tmp/minimized_seeds/guetzli guetzli 2>&1 | tee $(pwd)/tmp/minimized_seeds/guetzli.log

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/libjpeg $(pwd)/tmp/minimized_seeds/libjpeg libjpeg 2>&1 | tee $(pwd)/tmp/minimized_seeds/libjpeg.log

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/aspell $(pwd)/tmp/minimized_seeds/aspell aspell 2>&1 | tee $(pwd)/tmp/minimized_seeds/aspell.log

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/woff2_base $(pwd)/tmp/minimized_seeds/woff2_base woff2_base 2>&1 | tee $(pwd)/tmp/minimized_seeds/woff2_base.log

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/woff2_new $(pwd)/tmp/minimized_seeds/woff2_new woff2_new 2>&1 | tee $(pwd)/tmp/minimized_seeds/woff2_new.log

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/re2 $(pwd)/tmp/minimized_seeds/re2 re2 2>&1 | tee $(pwd)/tmp/minimized_seeds/re2.log

python3 eval.py minimize_seeds $(pwd)/tmp/seeds/seeds_fuzzer_mutation_analysis/vorbis $(pwd)/tmp/minimized_seeds/vorbis vorbis 2>&1 | tee $(pwd)/tmp/minimized_seeds/vorbis.log

