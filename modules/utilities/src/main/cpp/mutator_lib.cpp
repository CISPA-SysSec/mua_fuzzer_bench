//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/mutator_lib.h"
#include "mutations.h"


bool PatternMutator::isMutationLocation(Instruction* instr, json *seglist, int type) {
    auto segref = *seglist;
    if (segref["type"] == type) {
        return isMutationDebugLoc(instr, segref);
    } else {
        return false;
    }
}

bool PatternMutator::isMutationLocation(Instruction* instr, json *seglist, const std::vector<int>* types) {
    auto segref = *seglist;
    int givenType = segref["type"];
    for (auto type : *types) {
        if (givenType == type) {
            return isMutationDebugLoc(instr, segref);
        }
    }
    return false;
}

bool PatternMutator::isMutationDebugLoc(const Instruction *instr, const json &segref) {
    const DebugLoc &debugInfo = instr->getDebugLoc();
    if (debugInfo) {
        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        uint64_t line = debugInfo->getLine();
        uint64_t column = debugInfo->getColumn();
        return segref["directory"] == directory
               && segref["filePath"] == filePath
               && segref["line"] == line
               && segref["column"] == column;
    } else {
        return false; // if the debug loc does not exist, we cannot do a mutation
    }
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
        json *seglist,
        Module& M
)
{
    // TODO until further refactoring put call instruction mutations in here
    // TODO in future we should have one abstract class from which concrete mutators should inherit
    // TODO we just register the mutators here and call them, same for the pattern finder
    auto mutated = false;
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        auto calledFun = callinst->getCalledFunction();
        if (calledFun) {
            MallocPatternMutator Mmutator;
            FGetsPatternMutator FGmutator;
            PThreadPatternMutator PTmutator;
            mutated |= Mmutator.mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
            mutated |= FGmutator.mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
            mutated |= PTmutator.mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
        }
    }
    else if (auto* cmpinst = dyn_cast<ICmpInst>(instr)){
        GreaterThanPatternMutator GTmutator;
        LessThanPatternMutator LTmutator;
        mutated |= GTmutator.mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
        mutated |= LTmutator.mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
    } else {
        FreeArgumentReturnPatternMutator FARmutator;
        CMPXCHGPatternMutator CXCmutator;
        ATOMICRMWPatternMutator ARMWmutator;
        mutated |= FARmutator.mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
        mutated |= CXCmutator.mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
        mutated |= ARMWmutator.mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
    }
    return mutated;
}