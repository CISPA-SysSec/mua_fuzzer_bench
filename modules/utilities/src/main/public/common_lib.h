//
// Created by Abhilash Gupta on 28.05.21.
// Header containing common declarations to both mutator_lib and pattern_lib
//
#ifndef LLVM_MUTATION_TOOL_COMMON_LIB_H
#define LLVM_MUTATION_TOOL_COMMON_LIB_H

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

using namespace llvm;

void populatePatternVectors(bool cpp);
void insertMutationApiFunctions(Module& M, bool cpp);


#endif //LLVM_MUTATION_TOOL_COMMON_LIB_H