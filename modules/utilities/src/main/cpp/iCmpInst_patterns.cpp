#include "../public/pattern_lib.h"
#include "mutations.h"
#include "pattern_declarations.h"

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

/**
 * The mutator for both ICMP_SLT, ICMP_SLE will be the same
 * It changes one of the operators to cause an off-by-one error.
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @param icmpinst
 * @return
 */
bool LessThanEqualToPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == 40 || predicate == 41) {
        std::vector<int> typelist{SIGNED_LESS_THAN, SIGNED_LESS_THAN_EQUALTO};
        if (isMutationLocation(instr, seglist, &typelist)) {
            // add 1, multiply the whole value by 2 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            rhs = icmpinst->getOperand(1);
            auto newVal = builder->CreateAdd(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
            newVal = builder->CreateMul(newVal, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 2));
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}

std::vector<std::string> GreaterThanPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == 38) {
        results.push_back(getIdentifierString(instr, SIGNED_GREATER_THAN));
    }
    return results;
}

/**
 * The mutator for both ICMP_SGT, ICMP_SGE will be the same.
 * It changes one of the operators to cause an off-by one error.
 *
 */
bool GreaterThanPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == 38 || predicate == 39) {
        std::vector<int> typelist {SIGNED_GREATER_THAN, SIGNED_GREATER_THAN_EQUALTO};
        if (isMutationLocation(instr, seglist, &typelist)) {
            // substract 1 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            rhs = icmpinst->getOperand(1);
            auto newVal = builder->CreateSub(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}
