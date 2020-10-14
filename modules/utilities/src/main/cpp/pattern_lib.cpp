//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/pattern_lib.h"
#include <nlohmann/json.hpp>
#include "mutations.h"
using json = nlohmann::json;

std::string getIdentifierString(const Instruction *instr, int type, const std::string& additionalInfo = "");
std::string findMalloc(const Instruction *instr, const StringRef &funNameString);
std::string findPThread(const Instruction *instr, const StringRef &funNameString);
std::string findFGets(const Instruction *instr, const StringRef &funNameString);
std::string findLessThanEqualTo(const Instruction *instr, llvm::CmpInst::Predicate predicate);
std::string findGreaterThan(const Instruction *instr, llvm::CmpInst::Predicate predicate);
std::vector<std::string> findFreeArgumentReturn(const Instruction *instr);
std::string findCMPXCHG(const Instruction *instr);
std::string findATOMICRMW(const Instruction *instr);
/**
     * Mutate the given function call if a mutation pattern exists for the function.
     * @param builder the builder to add instruction in front of the call
     * @param nextInstructionBuilder the builder to add instructions after the call
     * @param instr the instruction to mutate (i.e. the function call)
     * @param funNameString the name of the function that is called
     * @return
 */
std::vector<std::string> look_for_pattern(
        Instruction* instr
        )
{
    auto results = std::vector<std::string>();
//    std::cout << "test\n";
//    std::cout << instr->getDebugLoc() << "\n";
//    std::cout << getIdentifierString(instr, 10) ;
//    std::cout << "test2\n";
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        auto calledFun = callinst->getCalledFunction();
        if (calledFun) {
            auto funNameString = calledFun->getName();
            results.push_back(findMalloc(instr, funNameString));
            results.push_back(findFGets(instr, funNameString));
            results.push_back(findPThread(instr, funNameString));
        }
    }
    else if (auto* icmpinst = dyn_cast<ICmpInst>(instr)){
        auto predicate = icmpinst->getPredicate();
        results.push_back(findLessThanEqualTo(instr, predicate));
        results.push_back(findGreaterThan(instr, predicate));
    } else {
        auto mutation_locations = findFreeArgumentReturn(instr);
        for (const auto& location : mutation_locations) {
            results.push_back(location);
        }
        results.push_back(findCMPXCHG(instr));
        results.push_back(findATOMICRMW(instr));
    }
    return results;
}

std::string getIdentifierString(const Instruction *instr, int type, const std::string& additionalInfo){
    const DebugLoc &debugInfo = instr->getDebugLoc();
    if (debugInfo) {
        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        uint32_t line = debugInfo->getLine();
        uint32_t column = debugInfo->getColumn();
        json j;
        j["directory"] = directory;
        j["filePath"] = filePath;
        j["line"] = line;
        j["type"] = type;
        j["additionalInfo"] = additionalInfo;
        return j.dump(4);
    } else {
        json j;
        j["directory"] = "no_debug_loc";
        j["filePath"] = "no_debug_loc";
        j["line"] = 0;
        j["type"] = 0;
        j["additionalInfo"] = additionalInfo;
        return j.dump(4);
    }
}

/**
 * Searches for returns, if one is found it signals the mutations engine to mutate the location
 * Mutation will be handled in the mutator, it will add a free in front of the return, freeing
 * one function argument. The freeing is done for each function argument individually if it is a pointer type.
 * @param instr
 * @return
 */
std::vector<std::string> findFreeArgumentReturn(const Instruction *instr) {
    auto results = std::vector<std::string>();
    if (auto returnInst = dyn_cast<ReturnInst>(instr)) {
        const Function *outerFunction = returnInst->getFunction();
        for (auto op = outerFunction->arg_begin(); op != outerFunction->arg_end(); op++) {
            if (op->getType()->isPointerTy()) {
                results.push_back(getIdentifierString(instr, FREE_FUNCTION_ARGUMENT, std::to_string(op->getArgNo())));
            }
        }
    }
    return results;
}

std::string findFGets(const Instruction *instr, const StringRef &funNameString) {
    if (funNameString.find("fgets") != std::string::npos) {
        return getIdentifierString(instr, FGETS_MATCH_BUFFER_SIZE);
    } else {
        return "";
    }
}

std::string findMalloc(const Instruction *instr, const StringRef &funNameString) {
    if (funNameString.find("malloc") != std::string::npos) {
        return getIdentifierString(instr, MALLOC);
    } else {
        return "";
    }
}

std::string findPThread(const Instruction *instr, const StringRef &funNameString) {
    const std::string &funNameStdString = instr->getFunction()->getName().str();
    if (pthreadFoundFunctions.find(funNameStdString) == pthreadFoundFunctions.end() // function was not used before
        && (funNameString.find("pthread_mutex_lock") != std::string::npos
        || funNameString.find("pthread_mutex_unlock") != std::string::npos)
    ) {
        pthreadFoundFunctions.insert(funNameStdString);
        return getIdentifierString(instr, PTHREAD_MUTEX, funNameStdString);
    } else {
        return "";
    }
}

std::string findCMPXCHG(const Instruction *instr) {
    const std::string &funNameStdString = instr->getFunction()->getName().str();
    if (pthreadFoundFunctions.find(funNameStdString) == pthreadFoundFunctions.end()) { // function was not used before
        if (dyn_cast<AtomicCmpXchgInst>(instr)) {
            return getIdentifierString(instr, ATOMIC_CMP_XCHG, funNameStdString);
        }
    }
    return "";
}

std::string findATOMICRMW(const Instruction *instr) {
    if (!foundAtomicRMW) { // atomicrmw was not found yet
        if (dyn_cast<AtomicRMWInst>(instr)) {
            return getIdentifierString(instr, ATOMICRMW_REPLACE);
        }
    }
    return "";
}

std::string findLessThanEqualTo(const Instruction *instr, const llvm::CmpInst::Predicate predicate) {
    if (predicate == 41) {
        return getIdentifierString(instr, SIGNED_LESS_THAN_EQUALTO);
    } else {
        return "";
    }
}

std::string findGreaterThan(const Instruction *instr, const llvm::CmpInst::Predicate predicate) {
    if (predicate == 38) {
        return getIdentifierString(instr, SIGNED_GREATER_THAN);
    } else {
        return "";
    }
}