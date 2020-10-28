#include "../public/pattern_lib.h"
#include "mutations.h"

std::vector<std::string> FreeArgumentReturnPattern::find(const Instruction *instr) {
    std::vector<std::string> results;
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

std::vector<std::string> CMPXCHGPattern::find(const Instruction *instr) {
    std::vector<std::string> results;
    // TODO: Does the next ling not need a check on the type of instruction? - abhilashgupta
    const std::string &funNameStdString = instr->getFunction()->getName().str();
    // TODO: Do we need to update the pthreadFoundFunctions after this check here? -abhilashgupta
    // Currently pthreadFoundFunctions is a protected member variable of the lowest common ancestor of
    // the classes CMPXCHGPattern and PThreadPattern. Move it accordingly.
    if (pthreadFoundFunctions.find(funNameStdString) == pthreadFoundFunctions.end()) { // function was not used before
        if (dyn_cast<AtomicCmpXchgInst>(instr)) {
            results.push_back(getIdentifierString(instr, ATOMIC_CMP_XCHG, funNameStdString));
        }
    }
    return results;
}

std::vector<std::string> ATOMICRMWPattern::find(const Instruction *instr) {
    std::vector<std::string> results;
    // TODO: The bool in the following check is always false. - abhilashgupta
    if (!foundAtomicRMW) { // atomicrmw was not found yet
        if (dyn_cast<AtomicRMWInst>(instr)) {
            results.push_back(getIdentifierString(instr, ATOMICRMW_REPLACE));
        }
    }
    return results;
}