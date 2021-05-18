#!/usr/bin/env bash

# build the mutator image (to be sure this could also rebuild the image)
#echo yes | ./mutator-docker-wrapper.py -s
#echo yes | ./mutator-docker-wrapper.py -b

sudo rm -rf ./tmp/*

docker rm dummy || true
docker create -ti --name dummy mutator_mutator bash
sudo rm -rf tmp/samples/ && docker cp dummy:/home/mutator/samples/ tmp/ && \
    docker cp dummy:/home/mutator/build/install/LLVM_Mutation_Tool/lib/ tmp/lib/
docker rm -f dummy

exec ./eval.py "eval" "$@"
