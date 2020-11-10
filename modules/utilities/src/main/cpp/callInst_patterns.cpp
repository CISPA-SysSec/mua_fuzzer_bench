#include "../public/pattern_lib.h"
#include "mutations.h"
#include "pattern_declarations.h"

void CallInstPattern::getfunNameString(const Instruction *instr){
    auto *callinst = dyn_cast<CallInst>(instr);
    auto calledFun = callinst->getCalledFunction();
    auto fNString = calledFun->getName();
    funNameString = fNString;
}

std::vector<std::string> MallocPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getfunNameString(instr);
    if (funNameString.find("malloc") != std::string::npos) {
        results.push_back(getIdentifierString(instr, MALLOC));
    }
    return results;
}

/**
 * On malloc it allocates one byte less memory.
 */
bool MallocPattern::mutate(
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
            addMutationFoundSignal(builder, M);
            auto newVal = builder->CreateAdd(lhs, builder->getInt64(-1));
            builderMutex.unlock();
            callinst->setOperand(0, newVal);
            return true;
        }
    }
    return false;
}

std::vector<std::string> FGetsPattern::find (const Instruction *instr) {
    std::vector<std::string> results;
    getfunNameString(instr);
    if (funNameString.find("fgets") != std::string::npos) {
        results.push_back(getIdentifierString(instr, FGETS_MATCH_BUFFER_SIZE));
    }
    return results;
}

/**
 * On fgets it allows to read more bytes than intended by the developer (concretely if X bytes should have been
 * read, (X+1)*5 bytes are read).
 */
bool FGetsPattern::mutate(
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
            addMutationFoundSignal(builder, M);
            auto newVal = builder->CreateAdd(lhs, builder->getInt64(1));
            newVal = builder->CreateMul(newVal, builder->getInt64(5));
            builderMutex.unlock();
            callinst->setOperand(1, newVal);
            return true;
        }
    }
    return false;
}

std::vector<std::string> PThreadPattern::find (const Instruction *instr) {
    std::vector<std::string> results;
    getfunNameString(instr);
    const std::string &funNameStdString = instr->getFunction()->getName().str();
    if (pthreadFoundFunctions.find(funNameStdString) == pthreadFoundFunctions.end() // function was not used before
        && (funNameString.find("pthread_mutex_lock") != std::string::npos
        || funNameString.find("pthread_mutex_unlock") != std::string::npos)
    ) {
        pthreadFoundFunctions.insert(funNameStdString);
        json j;
        j["funname"] = funNameStdString;
        results.push_back(getIdentifierString(instr, PTHREAD_MUTEX, j));
    }
    return results;
}


/**
 * For the given function it replaces all locks and unlocks in the function.
 */
bool PThreadPattern::mutate(
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
        && surroundingFunction == segref["additionalInfo"]["funname"]
        && (funNameString.find("pthread_mutex_lock") != std::string::npos
            || funNameString.find("pthread_mutex_unlock") != std::string::npos)
            ){
        builderMutex.lock();
        addMutationFoundSignal(builder, M);
        // the return value of the locking could be used somewhere, hence we need to make sure that this value still exists and simulates a successful lock
        instr->replaceAllUsesWith(builder->getInt32(1));
        // then we can remove the instruction from the parent
        instr->removeFromParent();
        builderMutex.unlock();
        return true;
    }
    return false;
}


std::vector<std::string> CallocPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getfunNameString(instr);
    if (funNameString.find("calloc") != std::string::npos) {
        results.push_back(getIdentifierString(instr, CALLOC));
    }
    return results;
}

/**
 * On calloc it allocates one byte less memory.
 */
bool CallocPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* callinst = dyn_cast<CallInst>(instr);
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.find("calloc") != std::string::npos) {
        if (isMutationLocation(instr, seglist, CALLOC)) {
            // substract 1 and give the new value to malloc
            Value* lhs;
            lhs = callinst->getArgOperand(1);
            builderMutex.lock();
            addMutationFoundSignal(builder, M);
            auto newVal = builder->CreateAdd(lhs, builder->getInt64(-1));
            builderMutex.unlock();
            callinst->setOperand(1, newVal);
            return true;
        }
    }
    return false;
}