#!/bin/sh

python3 build/install/LLVM_Mutation_Tool/bin/compileAndFind.py $1
python3 build/install/LLVM_Mutation_Tool/bin/Mutate.py $1
