#include "../public/pattern_lib.h"
#include "mutations.h"

void ICmpInstPattern::getpredicate(const Instruction *instr){
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    predicate = icmpinst->getPredicate();
}

std::vector<std::string> LessThanEqualToPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == 41) {
        results.push_back(getIdentifierString(instr, SIGNED_LESS_THAN_EQUALTO));
    }
    return results;
}

std::vector<std::string> GreaterThanPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == 38) {
        results.push_back(getIdentifierString(instr, SIGNED_GREATER_THAN));
    }
    return results;
}