//
// Created by Björn Mathis on 11.09.20.
//

#ifndef LLVM_MUTATION_TOOL_MUTATOR_LIB_H
#define LLVM_MUTATION_TOOL_MUTATOR_LIB_H

#include "common_lib.h"
#include <../dependencies/json.hpp>

using json = nlohmann::json;

bool mutatePattern(
    IRBuilder<>* builder,
    IRBuilder<>* nextInstructionBuilder,
    Instruction* instr,
    std::mutex& builderMutex,
    json *seglist,
    Module& M
);

#endif //LLVM_MUTATION_TOOL_MUTATOR_LIB_H
