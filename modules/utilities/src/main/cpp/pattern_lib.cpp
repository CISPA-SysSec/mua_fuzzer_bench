//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/pattern_lib.h"
#include "mutations.h"


std::string findMalloc(const Instruction *instr, const StringRef &funNameString);
std::string findFGets(const Instruction *instr, const StringRef &funNameString);
std::string findLessThanEqualTo(const Instruction *instr, const llvm::CmpInst::Predicate predicate);
std::string findGreaterThan(const Instruction *instr, const llvm::CmpInst::Predicate predicate);
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
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        auto funNameString = callinst->getCalledFunction()->getName();
        results.push_back(findMalloc(instr, funNameString));
        results.push_back(findFGets(instr, funNameString));
    }
    else if (auto* icmpinst = dyn_cast<ICmpInst>(instr)){
        auto predicate = icmpinst->getPredicate();
        results.push_back(findLessThanEqualTo(instr, predicate));
        results.push_back(findGreaterThan(instr, predicate));
    }
    return results;
}

std::string getIdentifierString(const Instruction *instr, std::string addendum){
    const DebugLoc &debugInfo = instr->getDebugLoc();

        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        uint32_t line = debugInfo->getLine();
        uint32_t column = debugInfo->getColumn();
        return directory + "|" +
               filePath + "|" +
               std::to_string(line) + "|" +
               std::to_string(column) + "|" +
               addendum + "\n";
}

std::string findFGets(const Instruction *instr, const StringRef &funNameString) {
    if (funNameString.find("fgets") != std::string::npos) {
        return getIdentifierString(instr, std::to_string(FGETS_MATCH_BUFFER_SIZE));
    } else {
        return "";
    }
}

std::string findMalloc(const Instruction *instr, const StringRef &funNameString) {
    if (funNameString.find("malloc") != std::string::npos) {
        return getIdentifierString(instr, std::to_string(MALLOC));
    } else {
        return "";
    }
}

std::string findLessThanEqualTo(const Instruction *instr, const llvm::CmpInst::Predicate predicate) {
    if (predicate == 41) {
        return getIdentifierString(instr, std::to_string(SIGNED_LESS_THAN_EQUALTO));
    } else {
        return "";
    }
}

std::string findGreaterThan(const Instruction *instr, const llvm::CmpInst::Predicate predicate) {
    if (predicate == 38) {
        return getIdentifierString(instr, std::to_string(SIGNED_GREATER_THAN));
    } else {
        return "";
    }
}