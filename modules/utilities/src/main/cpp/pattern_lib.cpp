//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/pattern_lib.h"
#include "pattern_declarations.h"
using json = nlohmann::json;


// smart pointers (unique_ptr) to make garbage collection automatic.
std::vector<std::unique_ptr<CallInstPattern>> CallInstPatterns;
std::vector<std::unique_ptr<ICmpInstPattern>> ICmpInstPatterns;
std::vector<std::unique_ptr<Pattern>> MiscInstPatterns;


// TODO: maybe refactor the populate functions into OOP. But only if required, later on.
// Add new CallInstPattern objects here as you add them.
void populateCallInstPatterns(){
    CallInstPatterns.push_back(std::make_unique <PThreadPattern>());
    CallInstPatterns.push_back(std::make_unique <MallocPattern>());
    CallInstPatterns.push_back(std::make_unique <CallocPattern>());
    CallInstPatterns.push_back(std::make_unique <FGetsPattern>());
    CallInstPatterns.push_back(std::make_unique <INetAddrFailPattern>());
}

// Add new ICmpInstPattern objects here as you add them.
void populateICmpInstPatterns(){
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedToUnsigned>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedToSigned>());
}

// Add new MiscInstPattern objects here as you add them.
void populateMiscInstPatterns(){
    MiscInstPatterns.push_back(std::make_unique <FreeArgumentReturnPattern>());
    MiscInstPatterns.push_back(std::make_unique <CMPXCHGPattern>());
    MiscInstPatterns.push_back(std::make_unique <ATOMICRMWPattern>());
    MiscInstPatterns.push_back(std::make_unique <ShiftSwitch>());
    MiscInstPatterns.push_back(std::make_unique <UnInitLocalVariables>());
    MiscInstPatterns.push_back(std::make_unique <CompareEqualToPattern>());
}

// Global function to call all the vector populators
void populatePatternVectors(){
    populateCallInstPatterns();
    populateICmpInstPatterns();
    populateMiscInstPatterns();
}

int Pattern::PatternIDCounter = 0;

std::string Pattern::getIdentifierString(const Instruction *instr, IRBuilder<>* builder, std::mutex& builderMutex, Module& M, int type){
    json j;
    return getIdentifierString(instr, builder, builderMutex, M, type, j);
}

std::string Pattern::getIdentifierString(const Instruction *instr, IRBuilder<>* builder, std::mutex& builderMutex, Module& M, int type, json& additionalInfo){
    const DebugLoc &debugInfo = instr->getDebugLoc();
    // currently the whole finder is locked
//    builderMutex.lock();
    addMutationFoundSignal(builder, M, PatternIDCounter);
//    builderMutex.unlock();
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
        j["type"] = type;
        j["additionalInfo"] = additionalInfo;
        j["UID"] = PatternIDCounter++;
    } else {
        j["directory"] = "no_debug_loc";
        j["filePath"] = "no_debug_loc";
        j["line"] = 0;
        j["column"] = 0;
        j["type"] = type;
        j["additionalInfo"] = additionalInfo;
        j["UID"] = PatternIDCounter++;
    }
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