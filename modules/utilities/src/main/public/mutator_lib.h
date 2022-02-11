//
// Created by Björn Mathis on 11.09.20.
//

#ifndef LLVM_MUTATION_TOOL_MUTATOR_LIB_H
#define LLVM_MUTATION_TOOL_MUTATOR_LIB_H

#include "common_lib.h"

bool mutatePattern(
    IRBuilder<>* builder,
    IRBuilder<>* nextInstructionBuilder,
    Instruction* instr,
    int id,
    std::mutex& builderMutex,
    Module& M
);

#endif //LLVM_MUTATION_TOOL_MUTATOR_LIB_H
