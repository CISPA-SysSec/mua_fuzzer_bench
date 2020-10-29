#include <iostream>
#include "../public/mutator_lib.h"
#include "mutations.h"

/**
 * On malloc it allocates one byte less memory.
 */
bool MallocPatternMutator::mutate(
    IRBuilder<>* builder,
    IRBuilder<>* nextInstructionBuilder,
    Instruction* instr,
    std::mutex& builderMutex,
    json *seglist,
    Module& M
) {
    auto* callinst = dyn_cast<CallInst>(instr);
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.find("malloc") != std::string::npos) {
        if (isMutationLocation(instr, seglist, MALLOC)) {
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
 * On fgets it allows to read more bytes than intended by the developer (concretely if X bytes should have been
 * read, (X+1)*5 bytes are read).
 */
bool FGetsPatternMutator::mutate(
    IRBuilder<>* builder,
    IRBuilder<>* nextInstructionBuilder,
    Instruction* instr,
    std::mutex& builderMutex,
    json *seglist,
    Module& M
) {
    auto* callinst = dyn_cast<CallInst>(instr);
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.find("fgets") != std::string::npos) {
        if (isMutationLocation(instr, seglist, FGETS_MATCH_BUFFER_SIZE)) {
            // add 1 to original value, multiply this new value by 5 and then
            // give the value to fgets
            Value* lhs;
            lhs = callinst->getArgOperand(1);
            builderMutex.lock();
            auto newVal = builder->CreateAdd(lhs, builder->getInt64(1));
            newVal = builder->CreateMul(newVal, builder->getInt64(5));
            builderMutex.unlock();
            callinst->setOperand(1, newVal);
            return true;
        }
    }
    return false;
}


/**
 * For the given function it replaces all locks and unlocks in the function.
 */
bool PThreadPatternMutator::mutate(
    IRBuilder<>* builder,
    IRBuilder<>* nextInstructionBuilder,
    Instruction* instr,
    std::mutex& builderMutex,
    json *seglist,
    Module& M
) {
    auto* callinst = dyn_cast<CallInst>(instr);
    auto funNameString = callinst->getCalledFunction()->getName();
    auto surroundingFunction = instr->getFunction()->getName().str();
    auto segref = *seglist;
    // we need a more fuzzy match here, the concrete location is not important, only the function
    if (segref["type"] == PTHREAD_MUTEX
        && surroundingFunction == segref["additionalInfo"]["extra_arg"]
        && (funNameString.find("pthread_mutex_lock") != std::string::npos
        || funNameString.find("pthread_mutex_unlock") != std::string::npos)
    ){
        builderMutex.lock();
        // the return value of the locking could be used somewhere, hence we need to make sure that this value still exists and simulates a successful lock
        instr->replaceAllUsesWith(builder->getInt32(1));
        // then we can remove the instruction from the parent
        instr->removeFromParent();
        builderMutex.unlock();
        return true;
    }
    return false;
}
