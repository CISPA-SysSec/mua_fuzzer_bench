//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/pattern_lib.h"
#include "pattern_list.h"
using json = nlohmann::json;

int Pattern::PatternIDCounter = 0;

std::string
Pattern::getFunctionNameSafe(Instruction *instr) {
    std::cout << "[INFO C] Instruction: " << instr << "\n" << std::flush;
    auto function = instr->getFunction();
    if (function and function->hasName()) {
        std::cout << "[INFO C] Function: " << function << "\n" << std::flush;
//        std::cout << "[INFO C] Instruction: " << function->getName() << "\n" << std::flush;
        std::cout << "[INFO C] Name: " << function->getName().str() << "\n" << std::flush;
        return function->getName().str();
    } else {
        return "DUMMYFUNCTION";
    }
}

std::string Pattern::getIdentifierString(const Instruction *instr, IRBuilder<>* builder, std::mutex& builderMutex, Module& M, int type){
    json j;
    return getIdentifierString(instr, builder, builderMutex, M, type, j);
}

std::string Pattern::getIdentifierString(const Instruction *instr, IRBuilder<>* builder, std::mutex& builderMutex, Module& M, int type, json& additionalInfo){
    // currently the whole finder is locked
//    builderMutex.lock();
    addMutationFoundSignal(builder, M, PatternIDCounter);
//    builderMutex.unlock();
    return getIdentifierString_unsignaled(instr, type, additionalInfo);
}

std::string Pattern::getIdentifierString_unsignaled(const Instruction *instr, int type){
    json j;
    return getIdentifierString_unsignaled(instr, type, j);
}

std::string Pattern::getIdentifierString_unsignaled(const Instruction *instr, int type, const json &additionalInfo) {
    const DebugLoc &debugInfo = instr->getDebugLoc();
    json j;
    if (debugInfo) {
        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        uint32_t line = debugInfo->getLine();
        uint32_t column = debugInfo->getColumn();
        j["directory"] = directory;
        j["filePath"] = filePath;
        j["line"] = line;
        j["column"] = column;
    } else {
        j["directory"] = "no_debug_loc";
        j["filePath"] = "no_debug_loc";
        j["line"] = 0;
        j["column"] = 0;
    }
    j["type"] = type;
    auto surroundingFunction = instr->getFunction()->getName().str();
    j["funname"] = surroundingFunction;
    std::string instructionString;
    raw_string_ostream os(instructionString);
    instr->print(os);
    j["instr"] = os.str();
    j["UID"] = PatternIDCounter++;
    j["additionalInfo"] = additionalInfo;
    return j.dump(4);
}

/**
     * Mutate the given function call if a mutation pattern exists for the function.
     * @param builder the builder to add instruction in front of the call
     * @param nextInstructionBuilder the builder to add instructions after the call
     * @param instr the instruction to mutate (i.e. the function call)
     * @param funNameString the name of the function that is called
     * @return
 */
// TODO: Maybe refactor this further to push down the inst check and make it one
// single loop on a single vector but only if required.
std::vector<std::string> look_for_pattern(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        Module& M
        )
{
    auto results = std::vector<std::string>();
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        auto calledFun = callinst->getCalledFunction();
        if (calledFun) {
            for (auto &patternobject : CallInstPatterns){
                for (auto &pattern : patternobject->find(instr, builder, builderMutex, M)){
                    results.push_back(pattern);
                }
            }
        }
    }
    else if (dyn_cast<ICmpInst>(instr)){
        for (auto &patternobject : ICmpInstPatterns){
            for (auto &pattern : patternobject->find(instr, builder, builderMutex, M)){
                results.push_back(pattern);
            }
        }
    }
    else{
        for (auto &patternobject : MiscInstPatterns){
            for (auto &pattern : patternobject->find(instr, builder, builderMutex, M)){
                results.push_back(pattern);
            }
        }
    }
    return results;
}