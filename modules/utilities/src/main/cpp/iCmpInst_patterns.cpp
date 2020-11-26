#include "../public/pattern_lib.h"
#include "mutations.h"
#include "pattern_declarations.h"

void ICmpInstPattern::getpredicate(const Instruction *instr){
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    predicate = icmpinst->getPredicate();
}

std::vector<std::string> SignedLessThanEqualToPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_SLE) {
        results.push_back(getIdentifierString(instr, SIGNED_LESS_THAN_EQUALTO));
    }
    return results;
}

/**
 * The mutator for ICMP_SLE.
 * It changes one of the operators to cause an off-by-one error.
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @param icmpinst
 * @return
 */
bool SignedLessThanEqualToPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_SLE) {
        if (isMutationLocation(instr, seglist, SIGNED_LESS_THAN_EQUALTO)) {
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

std::vector<std::string> SignedLessThanPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_SLT) {
        results.push_back(getIdentifierString(instr, SIGNED_LESS_THAN));
    }
    return results;
}

/**
 * The mutator for ICMP_SLT.
 * It changes one of the operators to cause an off-by-one error.
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @param icmpinst
 * @return
 */
bool SignedLessThanPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_SLT) {
        if (isMutationLocation(instr, seglist, SIGNED_LESS_THAN)) {
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

std::vector<std::string> UnsignedLessThanEqualToPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_ULE) {
        results.push_back(getIdentifierString(instr, UNSIGNED_LESS_THAN_EQUALTO));
    }
    return results;
}

/**
 * The mutator for ICMP_ULE.
 * It changes one of the operators to cause an off-by-one error.
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @param icmpinst
 * @return
 */
bool UnsignedLessThanEqualToPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_ULE) {
        if (isMutationLocation(instr, seglist, UNSIGNED_LESS_THAN_EQUALTO)) {
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


std::vector<std::string> UnsignedLessThanPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_ULT) {
        results.push_back(getIdentifierString(instr, UNSIGNED_LESS_THAN));
    }
    return results;
}



/**
 * The mutator for ICMP_ULT.
 * It changes one of the operators to cause an off-by-one error.
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @param icmpinst
 * @return
 */
bool UnsignedLessThanPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_ULT) {
        if (isMutationLocation(instr, seglist, UNSIGNED_LESS_THAN)) {
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


std::vector<std::string> SignedGreaterThanPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_SGT) {
        results.push_back(getIdentifierString(instr, SIGNED_GREATER_THAN));
    }
    return results;
}

/**
 * The mutator for ICMP_SGT.
 * It changes one of the operators to cause an off-by one error.
 */
bool SignedGreaterThanPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_SGT) {
        if (isMutationLocation(instr, seglist, SIGNED_GREATER_THAN)) {
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

std::vector<std::string> SignedGreaterThanEqualToPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_SGE) {
        results.push_back(getIdentifierString(instr, SIGNED_GREATER_THAN_EQUALTO));
    }
    return results;
}

/**
 * The mutator for ICMP_SGE.
 * It changes one of the operators to cause an off-by one error.
 */
bool SignedGreaterThanEqualToPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_SGE) {
        if (isMutationLocation(instr, seglist, SIGNED_GREATER_THAN_EQUALTO)) {
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

std::vector<std::string> UnsignedGreaterThanPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_UGT) {
        results.push_back(getIdentifierString(instr, UNSIGNED_GREATER_THAN));
    }
    return results;
}

/**
 * The mutator for ICMP_UGT.
 * It changes one of the operators to cause an off-by one error.
 */
bool UnsignedGreaterThanPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_UGT) {
        if (isMutationLocation(instr, seglist, UNSIGNED_GREATER_THAN)) {
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

std::vector<std::string> UnsignedGreaterThanEqualToPattern::find(const Instruction *instr){
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_UGE) {
        results.push_back(getIdentifierString(instr, UNSIGNED_GREATER_THAN_EQUALTO));
    }
    return results;
}

/**
 * The mutator for ICMP_UGE.
 * It changes one of the operators to cause an off-by one error.
 */
bool UnsignedGreaterThanEqualToPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_UGE) {
        if (isMutationLocation(instr, seglist, UNSIGNED_GREATER_THAN_EQUALTO)) {
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