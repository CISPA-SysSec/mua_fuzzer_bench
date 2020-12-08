//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/mutator_lib.h"
#include "pattern_declarations.h"

// smart pointers (unique_ptr) to make garbage collection automatic.
std::vector<std::unique_ptr<CallInstPattern>> CallInstMutators;
std::vector<std::unique_ptr<ICmpInstPattern>> ICmpInstMutators;
std::vector<std::unique_ptr<Pattern>> MiscInstMutators;

// TODO: maybe refactor the populate functions into OOP. But only if required, later on.
// Add new CallInstMutator objects here as you add them.
void populateCallInstMutators(){
    CallInstMutators.push_back(std::make_unique <PThreadPattern>());
    CallInstMutators.push_back(std::make_unique <MallocPattern>());
    CallInstMutators.push_back(std::make_unique <CallocPattern>());
    CallInstMutators.push_back(std::make_unique <FGetsPattern>());
}

// Add new ICmpInstMutator objects here as you add them.
void populateICmpInstMutators(){
    ICmpInstMutators.push_back(std::make_unique <SignedGreaterThanPattern>());
    ICmpInstMutators.push_back(std::make_unique <SignedGreaterThanEqualToPattern>());
    ICmpInstMutators.push_back(std::make_unique <SignedLessThanEqualToPattern>());
    ICmpInstMutators.push_back(std::make_unique <SignedLessThanPattern>());
    ICmpInstMutators.push_back(std::make_unique <UnsignedGreaterThanPattern>());
    ICmpInstMutators.push_back(std::make_unique <UnsignedGreaterThanEqualToPattern>());
    ICmpInstMutators.push_back(std::make_unique <UnsignedLessThanEqualToPattern>());
    ICmpInstMutators.push_back(std::make_unique <UnsignedLessThanPattern>());
    ICmpInstMutators.push_back(std::make_unique <SignedToUnsigned>());
    ICmpInstMutators.push_back(std::make_unique <UnsignedToSigned>());
}

// Add new MiscInstMutator objects here as you add them.
void populateMiscInstMutators(){
    MiscInstMutators.push_back(std::make_unique <FreeArgumentReturnPattern>());
    MiscInstMutators.push_back(std::make_unique <CMPXCHGPattern>());
    MiscInstMutators.push_back(std::make_unique <ATOMICRMWPattern>());
    MiscInstMutators.push_back(std::make_unique <ShiftSwitch>());
    MiscInstMutators.push_back(std::make_unique <UnInitLocalVariables>());
}

// Global function to call all the vector populators
void populateMutatorVectors(){
    populateCallInstMutators();
    populateICmpInstMutators();
    populateMiscInstMutators();
}

bool Pattern::isMutationLocation(Instruction* instr, json *seglist, int type) {
    auto segref = *seglist;
    if (segref["type"] == type) {
        return isMutationDebugLoc(instr, segref);
    } else {
        return false;
    }
}

bool Pattern::isMutationLocation(Instruction* instr, json *seglist, const std::vector<int>* types) {
    auto segref = *seglist;
    int givenType = segref["type"];
    for (auto type : *types) {
        if (givenType == type) {
            return isMutationDebugLoc(instr, segref);
        }
    }
    return false;
}

bool Pattern::isMutationDebugLoc(const Instruction *instr, const json &segref) {
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
 * A helper function that should be called whenever a mutation is done to signal that the mutation was triggered during
 * runtime.
 * @param builder
 * @param M
 */
void Pattern::addMutationFoundSignal(IRBuilder<> *builder, Module& M) {
        auto args = std::vector<Value*>();
        auto signalFunction = M.getFunction("signal_triggered_mutation");
        builder->CreateCall(signalFunction, args);
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
    else if (dyn_cast<ICmpInst>(instr)){
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

void insertMutationApiFunctions(Module& M) {
    LLVMContext &llvmContext = M.getContext();
    M.getOrInsertFunction("signal_triggered_mutation", Type::getVoidTy(llvmContext));
}