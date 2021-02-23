#!/usr/bin/env bash

set -Eeuxo pipefail

# container start:
# docker run -it --rm --ipc=host --env LD_LIBRARY_PATH=/workdir/lib/ -v $(pwd)/tmp/:/workdir/  mutator_testing bash

for filename in unsolved_mutants/*; do
    /usr/bin/clang++-11 -g -o mutants_build/$(basename "$filename").bin \
        /workdir/lib/libdynamiclibrary.so "$filename"
    objdump -Sdl -M intel mutants_build/$(basename "$filename").bin > mutants_dump/$(basename "$filename").txt
done
