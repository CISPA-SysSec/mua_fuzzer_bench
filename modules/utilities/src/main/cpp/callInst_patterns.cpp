#include "../public/pattern_lib.h"
#include "mutations.h"

void CallInstPatterns::getfunNameString(const Instruction *instr){
        auto *callinst = dyn_cast<CallInst>(instr);
        auto calledFun = callinst->getCalledFunction();
        auto fNString = calledFun->getName();
        funNameString = fNString;
}

std::vector<std::string> MallocPattern::find(const Instruction *instr){
    auto results = std::vector<std::string>();
    getfunNameString(instr);
    if (funNameString.find("malloc") != std::string::npos) {
        results.push_back(getIdentifierString(instr, MALLOC));
    }
    return results;
}

std::vector<std::string> FGetsPattern::find (const Instruction *instr) {
    auto results = std::vector<std::string>();
    getfunNameString(instr);
    if (funNameString.find("fgets") != std::string::npos) {
        results.push_back(getIdentifierString(instr, FGETS_MATCH_BUFFER_SIZE));
    }
    return results;
}

std::vector<std::string> PThreadPattern::find (const Instruction *instr) {
    auto results = std::vector<std::string>();
    getfunNameString(instr);
    const std::string &funNameStdString = instr->getFunction()->getName().str();
    if (pthreadFoundFunctions.find(funNameStdString) == pthreadFoundFunctions.end() // function was not used before
        && (funNameString.find("pthread_mutex_lock") != std::string::npos
        || funNameString.find("pthread_mutex_unlock") != std::string::npos)
    ) {
        pthreadFoundFunctions.insert(funNameStdString);
        results.push_back(getIdentifierString(instr, PTHREAD_MUTEX, funNameStdString));
    }
    return results;
}