//
// Created by Björn Mathis on 11.09.20.
//

#include "../public/pattern_lib.h"
#include "mutations.h"


/**
     * Mutate the given function call if a mutation pattern exists for the function.
     * @param builder the builder to add instruction in front of the call
     * @param nextInstructionBuilder the builder to add instructions after the call
     * @param instr the instruction to mutate (i.e. the function call)
     * @param funNameString the name of the function that is called
     * @return
 */
std::string look_for_pattern(
        Instruction* instr
        )
{
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        auto funNameString = callinst->getCalledFunction()->getName();
        if (funNameString.find("malloc") != std::string::npos) {
            const llvm::DebugLoc &debugInfo = instr->getDebugLoc();

            std::string directory = debugInfo->getDirectory().str();
            std::string filePath = debugInfo->getFilename().str();
            uint32_t line = debugInfo->getLine();
            uint32_t column = debugInfo->getColumn();
            return directory + "|" +
                   filePath + "|" +
                   std::to_string(line) + "|" +
                   std::to_string(column) + "|" +
                   std::to_string(MALLOC) + "\n";
        }
    }
    return "";
}