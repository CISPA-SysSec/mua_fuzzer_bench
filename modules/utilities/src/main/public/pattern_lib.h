//
// Created by Björn Mathis on 11.09.20.
//
#ifndef LLVM_MUTATION_TOOL_PATTERN_LIB_H
#define LLVM_MUTATION_TOOL_PATTERN_LIB_H


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
#include <set>

using namespace llvm;

std::vector<std::string> look_for_pattern(Instruction* instr);

std::set<std::string> pthreadFoundFunctions;
std::set<std::string> cmpxchgFoundFunctions;
bool foundAtomicRMW = false;


#endif //LLVM_MUTATION_TOOL_PATTERN_LIB_H
