//
// Created by Björn Mathis on 11.09.20.
//

#include "../public/mutator_lib.h"
#include "mutations.h"


/**
     * Mutate the given function call if a mutation pattern exists for the function.
     * @param builder the builder to add instruction in front of the call
     * @param nextInstructionBuilder the builder to add instructions after the call
     * @param instr the instruction to mutate (i.e. the function call)
     * @param funNameString the name of the function that is called
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
    auto segref = *seglist;
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
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
    }
    return false;
}