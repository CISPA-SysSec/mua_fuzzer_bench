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
    if (predicate == CmpInst::Predicate::ICMP_SLE) {
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
    if (predicate == CmpInst::Predicate::ICMP_SLT || predicate == CmpInst::Predicate::ICMP_SLE) {
        std::vector<int> typelist{SIGNED_LESS_THAN, SIGNED_LESS_THAN_EQUALTO};
        if (isMutationLocation(instr, seglist, &typelist)) {
            // add 1, multiply the whole value by 2 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            addMutationFoundSignal(builder, M);
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
    if (predicate == CmpInst::Predicate::ICMP_SGT) {
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
    if (predicate == CmpInst::Predicate::ICMP_SGT || predicate == CmpInst::Predicate::ICMP_SGE) {
        std::vector<int> typelist {SIGNED_GREATER_THAN, SIGNED_GREATER_THAN_EQUALTO};
        if (isMutationLocation(instr, seglist, &typelist)) {
            // substract 1 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            addMutationFoundSignal(builder, M);
            rhs = icmpinst->getOperand(1);
            auto newVal = builder->CreateSub(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}


std::vector<std::string> SignedToUnsigned::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_SGT || predicate == CmpInst::Predicate::ICMP_SGE
    || predicate == CmpInst::Predicate::ICMP_SLT || predicate == CmpInst::Predicate::ICMP_SLE) {
        results.push_back(getIdentifierString(instr, SIGNED_TO_UNSIGNED));
    }
    return results;
}

/**
 * Changes the comparison from signed to unsigned.
 *
 */
bool SignedToUnsigned::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_SGT || predicate == CmpInst::Predicate::ICMP_SGE
        || predicate == CmpInst::Predicate::ICMP_SLT || predicate == CmpInst::Predicate::ICMP_SLE) {
        std::vector<int> typelist {SIGNED_TO_UNSIGNED};
        if (isMutationLocation(instr, seglist, &typelist)) {
            // change from signed to unsigned
            builderMutex.lock();
            addMutationFoundSignal(builder, M);
            builderMutex.unlock();
            if (predicate == CmpInst::Predicate::ICMP_SGT) {
                builderMutex.lock();
                icmpinst->setPredicate(CmpInst::Predicate::ICMP_UGT);
                builderMutex.unlock();
            } else {
                if (predicate == CmpInst::Predicate::ICMP_SGE) {
                    builderMutex.lock();
                    icmpinst->setPredicate(CmpInst::Predicate::ICMP_UGE);
                    builderMutex.unlock();
                } else {
                    if (predicate == CmpInst::Predicate::ICMP_SLT) {
                        builderMutex.lock();
                        icmpinst->setPredicate(CmpInst::Predicate::ICMP_ULT);
                        builderMutex.unlock();
                    } else {
                        builderMutex.lock();
                        icmpinst->setPredicate(CmpInst::Predicate::ICMP_ULE);
                        builderMutex.unlock();
                    }
                }
            }
            return true;
        }
    }
    return false;
}


std::vector<std::string> UnsignedToSigned::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_UGT || predicate == CmpInst::Predicate::ICMP_UGE
        || predicate == CmpInst::Predicate::ICMP_ULT || predicate == CmpInst::Predicate::ICMP_ULE) {
        results.push_back(getIdentifierString(instr, UNSIGNED_TO_SIGNED));
    }
    return results;
}

/**
 * Changes the comparison from signed to unsigned.
 *
 */
bool UnsignedToSigned::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_UGT || predicate == CmpInst::Predicate::ICMP_UGE
        || predicate == CmpInst::Predicate::ICMP_ULT || predicate == CmpInst::Predicate::ICMP_ULE) {
        std::vector<int> typelist {UNSIGNED_TO_SIGNED};
        if (isMutationLocation(instr, seglist, &typelist)) {
            // change from signed to unsigned
            builderMutex.lock();
            addMutationFoundSignal(builder, M);
            builderMutex.unlock();
            if (predicate == CmpInst::Predicate::ICMP_UGT) {
                builderMutex.lock();
                icmpinst->setPredicate(CmpInst::Predicate::ICMP_SGT);
                builderMutex.unlock();
            } else {
                if (predicate == CmpInst::Predicate::ICMP_UGE) {
                    builderMutex.lock();
                    icmpinst->setPredicate(CmpInst::Predicate::ICMP_SGE);
                    builderMutex.unlock();
                } else {
                    if (predicate == CmpInst::Predicate::ICMP_ULT) {
                        builderMutex.lock();
                        icmpinst->setPredicate(CmpInst::Predicate::ICMP_SLT);
                        builderMutex.unlock();
                    } else {
                        builderMutex.lock();
                        icmpinst->setPredicate(CmpInst::Predicate::ICMP_SLE);
                        builderMutex.unlock();
                    }
                }
            }
            return true;
        }
    }
    return false;
}