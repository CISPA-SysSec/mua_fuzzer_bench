#!/usr/bin/env bash
set -euo pipefail

shopt -s globstar

progs=( "vorbis" "cares_name" "cares_parse_reply" "woff2_base" "libjpeg" )
fuzzers=( "afl" "aflpp_det" "aflpp_rec" "fairfuzz" "honggfuzz" )

rm -r tmp/seed_coverage || true
mkdir tmp/seed_coverage



################################################################################
# manually collected seed inputs / initial seeds
pushd tmp/seed_coverage
mkdir initial
pushd initial
# initial_seeds.zip: https://ruhr-uni-bochum.sciebo.de/s/3VX0sIEoUaBAi6k
wget -O seeds.zip https://ruhr-uni-bochum.sciebo.de/s/3VX0sIEoUaBAi6k/download
unzip -q seeds.zip -d seeds_tmp
rm seeds.zip

# mv the top level directory to seeds
find seeds_tmp -mindepth 1 -maxdepth 1 -type d -exec mv {} seeds \;
rmdir seeds_tmp
# flatten the seed inputs using the file hashes as names
mkdir -p hashed_seeds
pushd seeds
for prog in "${progs[@]}"; do
    echo "hashing seeds for $prog"
    mkdir -p "../hashed_seeds/$prog"
    find "$prog" -type f|while read file; do
    hash=$(shasum --algorithm 256 "$file" | cut -d ' ' -f1 )
    mv "$file" "../hashed_seeds/$prog/$hash"
    done
done
popd
rm -r seeds
mv hashed_seeds seeds

popd
popd

for prog in "${progs[@]}"; do
    echo "$prog"
    MUT_LOGS=1 python3 ./eval.py seed_coverage \
        --seed-path "tmp/seed_coverage/initial/seeds/$prog" \
        --res-path "tmp/seed_coverage/initial/result/$prog" \
        --prog "$prog"
done



################################################################################
# initial plus fuzzing generated seeds
pushd tmp/seed_coverage
mkdir fuzzed
pushd fuzzed
# fuzzed_seeds.zip: https://ruhr-uni-bochum.sciebo.de/s/L7aiykxpsIM8rFV
wget -O seeds.zip https://ruhr-uni-bochum.sciebo.de/s/L7aiykxpsIM8rFV/download
unzip -q seeds.zip -d seeds_tmp
rm seeds.zip

# mv the top level directory to seeds
find seeds_tmp -mindepth 1 -maxdepth 1 -type d -exec mv {} seeds \;
rmdir seeds_tmp
# flatten the seed inputs using the file hashes as names
mkdir -p hashed_seeds
pushd seeds
for prog in "${progs[@]}"; do
    echo "hashing seeds for $prog"
    mkdir -p "../hashed_seeds/$prog"
    find "$prog" -type f|while read file; do
    hash=$(shasum --algorithm 256 "$file" | cut -d ' ' -f1 )
    mv "$file" "../hashed_seeds/$prog/$hash"
    done
done
popd
rm -r seeds
mv hashed_seeds seeds

popd
popd

for prog in "${progs[@]}"; do
    echo "$prog"
    MUT_LOGS=1 python3 ./eval.py seed_coverage \
        --seed-path "tmp/seed_coverage/fuzzed/seeds/$prog" \
        --res-path "tmp/seed_coverage/fuzzed/result/$prog" \
        --prog "$prog"
done




################################################################################
# the final seed inputs for each program, split up by fuzzer
pushd tmp/seed_coverage
mkdir final
pushd final
# minimized_seeds_fuzzer.zip: https://ruhr-uni-bochum.sciebo.de/s/JwWE9jdiXBKP6F8
wget -O seeds.zip https://ruhr-uni-bochum.sciebo.de/s/JwWE9jdiXBKP6F8/download
unzip -q seeds.zip -d seeds_tmp
rm seeds.zip

# mv the top level directory to seeds
find seeds_tmp -mindepth 1 -maxdepth 1 -type d -exec mv {} seeds \;
rmdir seeds_tmp
# flatten the seed inputs using the file hashes as names
mkdir -p hashed_seeds
pushd seeds
for prog in "${progs[@]}"; do
    echo "$prog"
    pushd "$prog"
    pwd
    for fuzzer in "${fuzzers[@]}"; do
        echo "hashing seeds for $prog/$fuzzer"
        mkdir -p "../../hashed_seeds/$prog/$fuzzer"
        find "$fuzzer" -type f|while read file; do
        hash=$(shasum --algorithm 256 "$file" | cut -d ' ' -f1 )
        mv "$file" "../../hashed_seeds/$prog/$fuzzer/$hash"
        done
    done
    popd
done
popd
rm -r seeds
mv hashed_seeds seeds
popd
popd

for prog in "${progs[@]}"; do
    for fuzzer in "${fuzzers[@]}"; do
        echo "coverage data for $prog and $fuzzer"
        python3 ./eval.py seed_coverage \
            --seed-path "tmp/seed_coverage/final/seeds/$prog/$fuzzer" \
            --res-path "tmp/seed_coverage/final/result/$prog-$fuzzer" \
            --prog "$prog"
    done
done
