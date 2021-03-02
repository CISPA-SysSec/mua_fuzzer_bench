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
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanHalvedPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanEqualToHalvedPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedGreaterThanEqualToSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanEqualToSquaredPattern>());

    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanPattern>());
    ICmpInstPatterns.push_back(std::make_unique <SignedLessThanSquaredPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanHalvedPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanEqualToHalvedPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedGreaterThanEqualToSqrtPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanEqualToPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanEqualToSquaredPattern>());

    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanPattern>());
    ICmpInstPatterns.push_back(std::make_unique <UnsignedLessThanSquaredPattern>());

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