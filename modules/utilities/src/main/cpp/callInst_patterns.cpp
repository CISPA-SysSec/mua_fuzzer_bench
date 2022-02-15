#include "../public/pattern_lib.h"
#include "mutations.h"
#include "pattern_declarations.h"

void CallInstPattern::getfunNameString(const Instruction *instr){
    auto *callinst = dyn_cast<CallInst>(instr);
    auto calledFun = callinst->getCalledFunction();
    auto fNString = calledFun->getName();
    funNameString = fNString;
}

std::string CallInstPattern::demangle(const Instruction *instr)
{
    getfunNameString(instr);
    int status = -1;

    std::unique_ptr<char, void(*)(void*)> res { abi::__cxa_demangle(funNameString.str().c_str(), nullptr, nullptr, &status), std::free };
    return (status == 0) ? res.get() : funNameString.str();
}

std::vector<std::string>
MallocPattern::find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getfunNameString(instr);
    if (funNameString.str() == "malloc" || funNameString.str() == "\01_malloc") {
        results.push_back(getIdentifierString(instr, id, builder, builderMutex, M, MALLOC));
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
        Module& M
) {
    auto* callinst = dyn_cast<CallInst>(instr);
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.str() == "malloc" || funNameString.str() == "\01_malloc") {
        if (isMutationLocation(instr, &seglist, MALLOC)) {
            // substract 1 and give the new value to malloc
            Value* lhs;
            lhs = callinst->getArgOperand(0);
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            auto newVal = builder->CreateAdd(lhs, builder->getIntN(lhs->getType()->getIntegerBitWidth(), -16));
            builderMutex.unlock();
            callinst->setOperand(0, newVal);
            return true;
        }
    }
    return false;
}

std::vector<std::string>
FGetsPattern::find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getfunNameString(instr);
    if (funNameString.str() == "fgets" || funNameString.str() == "\01_fgets") {
        results.push_back(getIdentifierString(instr, id, builder, builderMutex, M, FGETS_MATCH_BUFFER_SIZE));
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
        Module& M
) {
    auto* callinst = dyn_cast<CallInst>(instr);
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.str() == "fgets" || funNameString.str() == "\01_fgets") {
        if (isMutationLocation(instr, &seglist, FGETS_MATCH_BUFFER_SIZE)) {
            // add 1 to original value, multiply this new value by 5 and then
            // give the value to fgets
            Value* lhs;
            lhs = callinst->getArgOperand(1);
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            auto newVal = builder->CreateAdd(lhs, builder->getIntN(lhs->getType()->getIntegerBitWidth(), 1));
            newVal = builder->CreateMul(newVal, builder->getIntN(lhs->getType()->getIntegerBitWidth(), 5));
            builderMutex.unlock();
            callinst->setOperand(1, newVal);
            return true;
        }
    }
    return false;
}

std::vector<std::string>
PThreadPattern::find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getfunNameString(instr);
    const std::string &funNameStdString = instr->getFunction()->getName().str();
    if (pthreadFoundFunctions.find(funNameStdString) == pthreadFoundFunctions.end() // function was not used before
        && (funNameString.str() == "pthread_mutex_lock" || funNameString.str() == "\01_pthread_mutex_lock"
        || funNameString.str() == "pthread_mutex_unlock" || funNameString.str() == "\01_pthread_mutex_unlock")
    ) {
        pthreadFoundFunctions.insert(funNameStdString);
        json j;
        j["funname"] = funNameStdString;
        results.push_back(getIdentifierString(instr, id, builder, builderMutex, M, PTHREAD_MUTEX, j));
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
        Module& M
) {
    auto* callinst = dyn_cast<CallInst>(instr);
    auto funNameString = callinst->getCalledFunction()->getName();
    auto surroundingFunction = instr->getFunction()->getName().str();
    auto segref = seglist;
    // we need a more fuzzy match here, the concrete location is not important, only the function
    if (segref["type"] == PTHREAD_MUTEX
        && surroundingFunction == segref["additionalInfo"]["funname"]
        && (funNameString.str() == "pthread_mutex_lock" || funNameString.str() == "\01_pthread_mutex_lock"
        || funNameString.str() == "pthread_mutex_unlock" || funNameString.str() == "\01_pthread_mutex_unlock")
            ){
        builderMutex.lock();
        addMutationFoundSignal(builder, M, segref["UID"]);
        // the return value of the locking could be used somewhere, hence we need to make sure that this value still exists and simulates a successful lock
        instr->replaceAllUsesWith(builder->getInt32(1));
        // then we can remove the instruction from the parent
        instr->removeFromParent();
        builderMutex.unlock();
        return true;
    }
    return false;
}


std::vector<std::string>
CallocPattern::find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getfunNameString(instr);
    if (funNameString.str() == "calloc" || funNameString.str() == "\01_calloc") {
        results.push_back(getIdentifierString(instr, id, builder, builderMutex, M, CALLOC));
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
        Module& M
) {
    auto* callinst = dyn_cast<CallInst>(instr);
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.str() == "calloc" || funNameString.str() == "\01_calloc") {
        if (isMutationLocation(instr, &seglist, CALLOC)) {
            // substract 1 and give the new value to malloc
            Value* lhs;
            lhs = callinst->getArgOperand(1);
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            auto newVal = builder->CreateAdd(lhs, builder->getIntN(lhs->getType()->getIntegerBitWidth(),-16));
            builderMutex.unlock();
            callinst->setOperand(1, newVal);
            return true;
        }
    }
    return false;
}

std::vector<std::string>
NewArrayPattern::find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getfunNameString(instr);
    std::string demangled_instr_name = demangle(instr);
    if (demangled_instr_name.find("operator new[]") != std::string::npos) {
        results.push_back(getIdentifierString(instr, id, builder, builderMutex, M, NEW_ARRAY));
    }
    return results;
}

/**
 * On new[] it allocates 5 units less memory.
 */
bool NewArrayPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        Module& M
) {
    auto* callinst = dyn_cast<CallInst>(instr);
    std::string demangled_instr_name = demangle(callinst);
    if (demangled_instr_name.find("operator new[]") != std::string::npos) {
        if (isMutationLocation(instr, &seglist, NEW_ARRAY)){
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            Value *op_val = callinst->getOperand(0);
            Value *newVal = builder->CreateSub(op_val, builder->getIntN(op_val->getType()->getIntegerBitWidth(), 5));
            callinst->setOperand(0, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}


std::vector<std::string>
DeleteCallInstructionPattern::find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex,
                                   Module &M) {
    std::vector<std::string> results;
    if (auto callInst = dyn_cast<CallInst>(instr)) {
        if (callInst->user_empty()) {
            results.push_back(getIdentifierString(instr, id, builder, builderMutex, M, DELETE_CALL_INSTRUCTION_PATTERN));
        }
    }
    return results;
}

/**
 * Delete the given store instruction to simulate a  forgotten variable assignment.
 */
bool DeleteCallInstructionPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        Module& M
        ) {
    auto segref = seglist;
    if (auto callInst = dyn_cast<CallInst>(instr)) {
        if (isMutationLocation(instr, &seglist, DELETE_CALL_INSTRUCTION_PATTERN)) {

            builderMutex.lock();
            addMutationFoundSignal(builder, M, segref["UID"]);
            // in this case when replacing all users, those can only be users that are llvm internal, no real users
            // i.e. llvm.dbg.value might use it, but not a real instruction like add or as a function argument in a call
            // hence we can safely replace it with an undef value, as the value should never be used in the real code/in execution
            callInst->replaceAllUsesWith(UndefValue::get(callInst->getType()));
            callInst->removeFromParent(); // we do not need to care about any users as there are none, we checked this in the find procedure
            builderMutex.unlock();

            return true;
        }
    }
    return false;
}