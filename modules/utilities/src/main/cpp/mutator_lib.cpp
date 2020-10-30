//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/mutator_lib.h"
#include "mutations.h"

// smart pointers (unique_ptr) to make garbage collection automatic.
std::vector<std::unique_ptr<PatternMutator>> CallInstMutators;
std::vector<std::unique_ptr<PatternMutator>> ICmpInstMutators;
std::vector<std::unique_ptr<PatternMutator>> MiscInstMutators;

// TODO: maybe refactor this into OOP. Only if required, later on.
//Add new CallInstMutators here as you add them.
void populateCallInstMutators(){
    CallInstMutators.push_back(std::make_unique <PThreadPatternMutator>());
    CallInstMutators.push_back(std::make_unique <MallocPatternMutator>());
    CallInstMutators.push_back(std::make_unique <FGetsPatternMutator>());
}

//Add new populateICmpInstMutators here as you add them.
void populateICmpInstMutators(){
    ICmpInstMutators.push_back(std::make_unique <GreaterThanPatternMutator>());
    ICmpInstMutators.push_back(std::make_unique <LessThanPatternMutator>());
}

//Add new populateMiscInstMutators here as you add them.
void populateMiscInstMutators(){
    MiscInstMutators.push_back(std::make_unique <FreeArgumentReturnPatternMutator>());
    MiscInstMutators.push_back(std::make_unique <CMPXCHGPatternMutator>());
    MiscInstMutators.push_back(std::make_unique <ATOMICRMWPatternMutator>());
}

//Global function to call all the vector populators
void populateMutatorVectors(){
    populateCallInstMutators();
    populateICmpInstMutators();
    populateMiscInstMutators();
}

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
    auto mutated = false;
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        auto calledFun = callinst->getCalledFunction();
        if (calledFun) {
            for (auto &mutator : CallInstMutators){
                mutated |= mutator->mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
            }
        }
    }
    else if (auto* cmpinst = dyn_cast<ICmpInst>(instr)){
        for (auto &mutator : ICmpInstMutators){
                mutated |= mutator->mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
        }
    } else {
        for (auto &mutator : MiscInstMutators){
                mutated |= mutator->mutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
        }
    }
    return mutated;
}