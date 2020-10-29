#include <iostream>
#include "../public/mutator_lib.h"
#include "mutations.h"

/* CmpInst predicate types enum in llvm
 * Predicate : unsigned {
 * FCMP_FALSE = 0, FCMP_OEQ = 1, FCMP_OGT = 2, FCMP_OGE = 3,
 * FCMP_OLT = 4, FCMP_OLE = 5, FCMP_ONE = 6, FCMP_ORD = 7,
 * FCMP_UNO = 8, FCMP_UEQ = 9, FCMP_UGT = 10, FCMP_UGE = 11,
 * FCMP_ULT = 12, FCMP_ULE = 13, FCMP_UNE = 14, FCMP_TRUE = 15,
 * FIRST_FCMP_PREDICATE = FCMP_FALSE, LAST_FCMP_PREDICATE = FCMP_TRUE, BAD_FCMP_PREDICATE = FCMP_TRUE + 1, ICMP_EQ = 32,
 * ICMP_NE = 33, ICMP_UGT = 34, ICMP_UGE = 35, ICMP_ULT = 36,
 * ICMP_ULE = 37, ICMP_SGT = 38, ICMP_SGE = 39, ICMP_SLT = 40,
 * ICMP_SLE = 41, FIRST_ICMP_PREDICATE = ICMP_EQ, LAST_ICMP_PREDICATE = ICMP_SLE, BAD_ICMP_PREDICATE = ICMP_SLE + 1
 * }
 */


/**
 * The mutator for both ICMP_SGT, ICMP_SGE will be the same.
 * It changes one of the operators to cause an off-by one error.
 *
 */
bool GreaterThanPatternMutator::mutate(
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
bool LessThanPatternMutator::mutate(
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