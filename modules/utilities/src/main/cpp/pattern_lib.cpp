//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/pattern_lib.h"
#include "mutations.h"
#include "../dependencies/json.hpp"
using json = nlohmann::json;



std::string Patterns::getIdentifierString(const Instruction *instr, int type, const std::string& additionalInfo){
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
        j["column"] = column;
        j["type"] = type;
        j["additionalInfo"] = { {"extra_arg", additionalInfo} };
        return j.dump(4);
    } else {
        json j;
        j["directory"] = "no_debug_loc";
        j["filePath"] = "no_debug_loc";
        j["line"] = 0;
        j["column"] = 0;
        j["type"] = type;
        j["additionalInfo"] = { {"extra_arg", additionalInfo} };
        return j.dump(4);
    }
}

/**
     * Mutate the given function call if a mutation pattern exists for the function.
     * @param builder the builder to add instruction in front of the call
     * @param nextInstructionBuilder the builder to add instructions after the call
     * @param instr the instruction to mutate (i.e. the function call)
     * @param funNameString the name of the function that is called
     * @return
 */
//TODO: Refactor this to loop through a vector (or vectors) of objects
std::vector<std::string> look_for_pattern(
        Instruction* instr
        )
{
    auto results = std::vector<std::string>();
    int i = 1;
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        auto calledFun = callinst->getCalledFunction();
        if (calledFun) {
            MallocPattern Mpattern;
            for (auto& pattern : Mpattern.find(instr))
            {
                std::cout<<i<<std::endl;
                std::cout<<pattern<<std::endl;
                results.push_back(pattern);
                i++;
            }
            FGetsPattern FGpattern;
            for (auto& pattern : FGpattern.find(instr))
            {
                std::cout<<i<<std::endl;
                std::cout<<pattern<<std::endl;
                results.push_back(pattern);
                i++;
            }
            PThreadPattern PTpattern;
            for (auto& pattern : PTpattern.find(instr))
            {
                std::cout<<i<<std::endl;
                std::cout<<pattern<<std::endl;
                results.push_back(pattern);
                i++;
            }
        }
    }
    else if (auto* icmpinst = dyn_cast<ICmpInst>(instr)){
        LessThanEqualToPattern LTETpattern;
        for (auto& pattern : LTETpattern.find(instr))
        {
            std::cout<<i<<std::endl;
            std::cout<<pattern<<std::endl;
            results.push_back(pattern);
            i++;
        }
        GreaterThanPattern GTpattern;
        for (auto& pattern : GTpattern.find(instr))
        {
            std::cout<<i<<std::endl;
            std::cout<<pattern<<std::endl;
            results.push_back(pattern);
            i++;
        }
    }
    else{
        FreeArgumentReturnPattern FARpattern;
        for (auto& pattern : FARpattern.find(instr))
        {
            std::cout<<i<<std::endl;
            std::cout<<pattern<<std::endl;
            results.push_back(pattern);
            i++;
        }
        CMPXCHGPattern Cpattern;
        for (auto& pattern : Cpattern.find(instr))
        {
            std::cout<<i<<std::endl;
            std::cout<<pattern<<std::endl;
            results.push_back(pattern);
            i++;
        }
        ATOMICRMWPattern ARMWpattern;
        for (auto& pattern : ARMWpattern.find(instr))
        {
            std::cout<<i<<std::endl;
            std::cout<<pattern<<std::endl;
            results.push_back(pattern);
            i++;
        }
    }
    return results;
}