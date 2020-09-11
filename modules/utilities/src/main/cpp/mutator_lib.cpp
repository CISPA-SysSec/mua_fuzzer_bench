//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/mutator_lib.h"
#include "mutations.h"


bool mutateMalloc(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        std::vector<std::string>* seglist,
        CallInst* callinst
) {
    auto segref = *seglist;
    std::cout << std::to_string((uint64_t)callinst) << " called\n\n";
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.find("malloc") != std::string::npos) {
        const llvm::DebugLoc &debugInfo = instr->getDebugLoc();
        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        int line = debugInfo->getLine();
        int column = debugInfo->getColumn();

        if (segref[0] == directory
            && segref[1] == filePath
            && std::stoi(segref[2]) == line
            && std::stoi(segref[3]) == column
            && std::stoi(segref[4]) == MALLOC) {
            // substract 1 and give the new value to malloc
            Value* lhs;
            lhs = callinst->getArgOperand(0);
            builderMutex.lock();
            auto newVal = builder->CreateAdd(lhs, builder->getInt64(-1));
            builderMutex.unlock();
            callinst->setOperand(0, newVal);
            return true;
        }
    }
    return false;
}



/**
     * Mutate the given function call if a mutation pattern exists for the function.
     * @param builder the builder to add instruction in front of the call
     * @param nextInstructionBuilder the builder to add instructions after the call
     * @param instr the instruction to mutate (i.e. the function call)
     * @param seglist the list of mutation locations, each mutator can decide upon the list if it should mutate the loc
     * @return
     */
bool mutatePattern(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        std::vector<std::string>* seglist
)
{
    std::cout << "test\n\n";
    // TODO until further refactoring put call instruction mutations in here
    // TODO in future we should have one abstract class from which concrete mutators should inherit
    // TODO we just register the mutators here and call them, same for the pattern finder
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        mutateMalloc(builder, nextInstructionBuilder, instr, builderMutex, seglist, callinst);
    }
}