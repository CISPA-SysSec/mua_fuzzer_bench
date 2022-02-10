//
// Created by Björn Mathis on 11.09.20.
//
#ifndef LLVM_MUTATION_TOOL_PATTERN_LIB_H
#define LLVM_MUTATION_TOOL_PATTERN_LIB_H

#include "common_lib.h"
#include <set>

std::vector<std::string> look_for_pattern(IRBuilder<>* builder,
                                          IRBuilder<>* nextInstructionBuilder,
                                          Instruction* instr,
                                          int id,
                                          std::mutex& builderMutex,
                                          Module& M);

#endif //LLVM_MUTATION_TOOL_PATTERN_LIB_H
