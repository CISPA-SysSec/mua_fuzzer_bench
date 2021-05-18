//
// Created by Björn Mathis on 11.09.20.
//

#ifndef LLVM_MUTATION_TOOL_MUTATOR_LIB_H
#define LLVM_MUTATION_TOOL_MUTATOR_LIB_H



#include <llvm/Pass.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <../dependencies/json.hpp>

using json = nlohmann::json;
using namespace llvm;

bool mutatePattern(
    IRBuilder<>* builder,
    IRBuilder<>* nextInstructionBuilder,
    Instruction* instr,
    std::mutex& builderMutex,
    json *seglist,
    Module& M
);

void populatePatternVectors(bool cpp);
void insertMutationApiFunctions(Module& M, bool cpp);

#endif //LLVM_MUTATION_TOOL_MUTATOR_LIB_H
