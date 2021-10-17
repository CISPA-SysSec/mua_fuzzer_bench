#include "../public/pattern_lib.h"
#include "mutations.h"
#include "pattern_declarations.h"

void ICmpInstPattern::getpredicate(const Instruction *instr){
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    predicate = icmpinst->getPredicate();
}

bool ICmpInstPattern::isMutateable(const CmpInst::Predicate pred, const Instruction* instr) {
    if (predicate == pred) {
        auto* icmpinst = dyn_cast<ICmpInst>(instr);
        auto rhs = icmpinst->getOperand(1);
        return rhs->getType()->isPointerTy() || rhs->getType()->isIntegerTy();
    } else {
        return false;
    }
}

Value* ICmpInstPattern::insertMutationFunctionCall(Value* toMutate, IRBuilder<> *builder, Module &M, const std::string& function) {
    auto args = std::vector<Value*>();
    auto bitcasted = builder->CreateZExtOrTrunc(toMutate, Type::getInt64Ty(M.getContext()));
    args.push_back(bitcasted);
    auto funToCall = M.getFunction(function);
    auto result = builder->CreateCall(funToCall, args);
    return builder->CreateZExtOrTrunc(result, toMutate->getType());
}

std::vector<std::string>
SignedLessThanEqualToPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex,
                                   Module &M) {
    std::vector<std::string> results;
    getpredicate(instr);
    if (isMutateable(CmpInst::Predicate::ICMP_SLE, instr)) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_LESS_THAN_EQUALTO));
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
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_SLE) {
        if (isMutationLocation(instr, &seglist, SIGNED_LESS_THAN_EQUALTO)) {
            // add 1, multiply the whole value by 2 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            rhs = icmpinst->getOperand(1);
            Value *newVal;
            if (rhs->getType()->isPointerTy()){
                LLVMContext &llvmContext = M.getContext();
                auto int_type = IntegerType::get (llvmContext, 32);
                Value* indexList = ConstantInt::get(int_type, 8);
                newVal = builder->CreateGEP(rhs, indexList);
            }
            else if (rhs->getType()->isIntegerTy()){
                newVal = insertMutationFunctionCall(rhs, builder, M, "mutate_square_add");
//                newVal = builder->CreateAdd(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateMul(newVal, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 2));
            }
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}

//std::vector<std::string>
//SignedLessThanEqualToSquaredPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex,
//                                   Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_SLE, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_LESS_THAN_EQUALTO_SQUARED));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_SLE.
// * It changes one of the operators to cause an incorrect memory access error.
// * @param builder
// * @param nextInstructionBuilder
// * @param instr
// * @param builderMutex
// * @param seglist
// * @param icmpinst
// * @return
// */
//bool SignedLessThanEqualToSquaredPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_SLE) {
//        if (isMutationLocation(instr, &seglist, SIGNED_LESS_THAN_EQUALTO_SQUARED)) {
//            // add 1, multiply the whole value by 2 and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, 8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateAdd(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateMul(newVal, newVal);
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}

std::vector<std::string>
SignedLessThanPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getpredicate(instr);
    if (isMutateable(CmpInst::Predicate::ICMP_SLT, instr)) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_LESS_THAN));
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
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_SLT) {
        if (isMutationLocation(instr, &seglist, SIGNED_LESS_THAN)) {
            // add 1, multiply the whole value by 2 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            rhs = icmpinst->getOperand(1);
            Value *newVal;
            if (rhs->getType()->isPointerTy()){
                LLVMContext &llvmContext = M.getContext();
                auto int_type = IntegerType::get (llvmContext, 32);
                Value* indexList = ConstantInt::get(int_type, 8);
                newVal = builder->CreateGEP(rhs, indexList);
            }
            else if (rhs->getType()->isIntegerTy()){
                newVal = insertMutationFunctionCall(rhs, builder, M, "mutate_square_add");
//                newVal = builder->CreateAdd(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateMul(newVal, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 2));
            }
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}

//std::vector<std::string>
//SignedLessThanSquaredPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_SLT, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_LESS_THAN_SQUARED));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_SLT.
// * It changes one of the operators to cause an off-by-one error.
// * @param builder
// * @param nextInstructionBuilder
// * @param instr
// * @param builderMutex
// * @param seglist
// * @param icmpinst
// * @return
// */
//bool SignedLessThanSquaredPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_SLT) {
//        if (isMutationLocation(instr, &seglist, SIGNED_LESS_THAN_SQUARED)) {
//            // add 1, multiply the whole value by 2 and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, 8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateAdd(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateMul(newVal, newVal);
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}

std::vector<std::string>
UnsignedLessThanEqualToPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex,
                                     Module &M) {
    std::vector<std::string> results;
    getpredicate(instr);
    if (isMutateable(CmpInst::Predicate::ICMP_ULE, instr)) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_LESS_THAN_EQUALTO));
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
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_ULE) {
        if (isMutationLocation(instr, &seglist, UNSIGNED_LESS_THAN_EQUALTO)) {
            // add 1, multiply the whole value by 2 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            rhs = icmpinst->getOperand(1);
            Value *newVal;
            if (rhs->getType()->isPointerTy()){
                LLVMContext &llvmContext = M.getContext();
                auto int_type = IntegerType::get (llvmContext, 32);
                Value* indexList = ConstantInt::get(int_type, 8);
                newVal = builder->CreateGEP(rhs, indexList);
            }
            else if (rhs->getType()->isIntegerTy()){
                newVal = insertMutationFunctionCall(rhs, builder, M, "mutate_square_add");
//                newVal = builder->CreateAdd(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateMul(newVal, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 2));
            }
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}

//std::vector<std::string>
//UnsignedLessThanEqualToSquaredPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex,
//                                     Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_ULE, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_LESS_THAN_EQUALTO_SQUARED));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_ULE.
// * It changes one of the operators to cause an off-by-one error.
// * @param builder
// * @param nextInstructionBuilder
// * @param instr
// * @param builderMutex
// * @param seglist
// * @param icmpinst
// * @return
// */
//bool UnsignedLessThanEqualToSquaredPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_ULE) {
//        if (isMutationLocation(instr, &seglist, UNSIGNED_LESS_THAN_EQUALTO_SQUARED)) {
//            // add 1, multiply the whole value by 2 and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, 8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateAdd(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateMul(newVal, newVal);
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}


std::vector<std::string>
UnsignedLessThanPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getpredicate(instr);
    if (isMutateable(CmpInst::Predicate::ICMP_ULT, instr)) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_LESS_THAN));
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
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_ULT) {
        if (isMutationLocation(instr, &seglist, UNSIGNED_LESS_THAN)) {
            // add 1, multiply the whole value by 2 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            rhs = icmpinst->getOperand(1);
            Value *newVal;
            if (rhs->getType()->isPointerTy()){
                LLVMContext &llvmContext = M.getContext();
                auto int_type = IntegerType::get (llvmContext, 32);
                Value* indexList = ConstantInt::get(int_type, 8);
                newVal = builder->CreateGEP(rhs, indexList);
            }
            else if (rhs->getType()->isIntegerTy()){
                newVal = insertMutationFunctionCall(rhs, builder, M, "mutate_square_add");
//                newVal = builder->CreateAdd(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateMul(newVal, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 2));
            }
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}

//std::vector<std::string>
//UnsignedLessThanSquaredPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_ULT, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_LESS_THAN_SQUARED));
//    }
//    return results;
//}
//
//
//
///**
// * The mutator for ICMP_ULT.
// * It changes one of the operators to cause an off-by-one error.
// * @param builder
// * @param nextInstructionBuilder
// * @param instr
// * @param builderMutex
// * @param seglist
// * @param icmpinst
// * @return
// */
//bool UnsignedLessThanSquaredPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_ULT) {
//        if (isMutationLocation(instr, &seglist, UNSIGNED_LESS_THAN_SQUARED)) {
//            // add 1, multiply the whole value by 2 and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, 8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateAdd(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateMul(newVal, newVal);
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}


std::vector<std::string>
SignedGreaterThanPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getpredicate(instr);
    if (isMutateable(CmpInst::Predicate::ICMP_SGT, instr)) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_GREATER_THAN));
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
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_SGT) {
        if (isMutationLocation(instr, &seglist, SIGNED_GREATER_THAN)) {
            // substract 1 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            rhs = icmpinst->getOperand(1);
            Value *newVal;
            if (rhs->getType()->isPointerTy()){
                LLVMContext &llvmContext = M.getContext();
                auto int_type = IntegerType::get (llvmContext, 32);
                Value* indexList = ConstantInt::get(int_type, -8);
                newVal = builder->CreateGEP(rhs, indexList);
            }
            else if (rhs->getType()->isIntegerTy()){
                newVal = insertMutationFunctionCall(rhs, builder, M, "mutate_root_half_sub");
//                newVal = builder->CreateSub(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
            }
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}

//std::vector<std::string>
//SignedGreaterThanHalvedPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_SGT, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_GREATER_THAN_HALVED));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_SGT.
// * It changes one of the operators to cause an off-by one error.
// */
//bool SignedGreaterThanHalvedPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_SGT) {
//        if (isMutationLocation(instr, &seglist, SIGNED_GREATER_THAN_HALVED)) {
//            // half and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, -8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateSDiv(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 2));
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}

//std::vector<std::string>
//SignedGreaterThanSqrtPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_SGT, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_GREATER_THAN_SQRT));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_SGT.
// * It changes one of the operators to cause an off-by one error.
// */
//bool SignedGreaterThanSqrtPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_SGT) {
//        if (isMutationLocation(instr, &seglist, SIGNED_GREATER_THAN_SQRT)) {
//            // half and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, -8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateLShr(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateSIToFP(newVal, Type::getDoubleTy(M.getContext()));
//                std::vector<Type *> types;
//                types.push_back(Type::getDoubleTy(M.getContext()));
//                types.push_back(Type::getDoubleTy(M.getContext()));
//                auto sqrtFun = Intrinsic::getDeclaration(&M, Intrinsic::sqrt, types);
//                std::vector<Value *> args;
//                args.push_back(newVal);
//                newVal = builder->CreateCall(sqrtFun, args);
//                newVal = builder->CreateFPToSI(newVal, rhs->getType());
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}

std::vector<std::string>
SignedGreaterThanEqualToPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex,
                                      Module &M) {
    std::vector<std::string> results;
    getpredicate(instr);
    if (isMutateable(CmpInst::Predicate::ICMP_SGE, instr)) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_GREATER_THAN_EQUALTO));
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
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_SGE) {
        if (isMutationLocation(instr, &seglist, SIGNED_GREATER_THAN_EQUALTO)) {
            // substract 1 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            rhs = icmpinst->getOperand(1);
            Value *newVal;
            if (rhs->getType()->isPointerTy()){
                LLVMContext &llvmContext = M.getContext();
                auto int_type = IntegerType::get (llvmContext, 32);
                Value* indexList = ConstantInt::get(int_type, -8);
                newVal = builder->CreateGEP(rhs, indexList);
            }
            else if (rhs->getType()->isIntegerTy()){
                newVal = insertMutationFunctionCall(rhs, builder, M, "mutate_root_half_sub");
//                newVal = builder->CreateSub(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
            }
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}

//std::vector<std::string>
//SignedGreaterThanEqualToHalvedPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex,
//                                      Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_SGE, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_GREATER_THAN_EQUALTO_HALVED));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_SGE.
// * It changes one of the operators to cause an off-by one error.
// */
//bool SignedGreaterThanEqualToHalvedPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_SGE) {
//        if (isMutationLocation(instr, &seglist, SIGNED_GREATER_THAN_EQUALTO_HALVED)) {
//            // half and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, -8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateSDiv(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 2));
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}
//
//std::vector<std::string>
//SignedGreaterThanEqualToSqrtPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex,
//                                            Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_SGE, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_GREATER_THAN_EQUALTO_SQRT));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_SGE.
// * It changes one of the operators to cause an off-by one error.
// */
//bool SignedGreaterThanEqualToSqrtPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_SGE) {
//        if (isMutationLocation(instr, &seglist, SIGNED_GREATER_THAN_EQUALTO_SQRT)) {
//            // half and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, -8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateLShr(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateSIToFP(newVal, Type::getDoubleTy(M.getContext()));
//                std::vector<Type *> types;
//                types.push_back(Type::getDoubleTy(M.getContext()));
//                types.push_back(Type::getDoubleTy(M.getContext()));
//                auto sqrtFun = Intrinsic::getDeclaration(&M, Intrinsic::sqrt, types);
//                std::vector<Value *> args;
//                args.push_back(newVal);
//                newVal = builder->CreateCall(sqrtFun, args);
//                newVal = builder->CreateFPToSI(newVal, rhs->getType());
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}

std::vector<std::string>
UnsignedGreaterThanPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getpredicate(instr);
    if (isMutateable(CmpInst::Predicate::ICMP_UGT, instr)) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_GREATER_THAN));
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
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_UGT) {
        if (isMutationLocation(instr, &seglist, UNSIGNED_GREATER_THAN)) {
            // substract 1 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            rhs = icmpinst->getOperand(1);
            Value *newVal;
            if (rhs->getType()->isPointerTy()){
                LLVMContext &llvmContext = M.getContext();
                auto int_type = IntegerType::get (llvmContext, 32);
                Value* indexList = ConstantInt::get(int_type, -8);
                newVal = builder->CreateGEP(rhs, indexList);
            }
            else if (rhs->getType()->isIntegerTy()){
                newVal = insertMutationFunctionCall(rhs, builder, M, "mutate_root_half_sub");
//                newVal = builder->CreateSub(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
            }
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}
//
//std::vector<std::string>
//UnsignedGreaterThanHalvedPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_UGT, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_GREATER_THAN_HALVED));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_UGT.
// * It changes one of the operators to cause an off-by one error.
// */
//bool UnsignedGreaterThanHalvedPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_UGT) {
//        if (isMutationLocation(instr, &seglist, UNSIGNED_GREATER_THAN_HALVED)) {
//            // substract 1 and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, -8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateUDiv(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 2));
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}
//
//std::vector<std::string>
//UnsignedGreaterThanSqrtPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_UGT, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_GREATER_THAN_SQRT));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_UGT.
// * It changes one of the operators to cause an off-by one error.
// */
//bool UnsignedGreaterThanSqrtPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_UGT) {
//        if (isMutationLocation(instr, &seglist, UNSIGNED_GREATER_THAN_SQRT)) {
//            // substract 1 and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, -8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateLShr(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateUIToFP(newVal, Type::getDoubleTy(M.getContext()));
//                std::vector<Type *> types;
//                types.push_back(Type::getDoubleTy(M.getContext()));
//                types.push_back(Type::getDoubleTy(M.getContext()));
//                auto sqrtFun = Intrinsic::getDeclaration(&M, Intrinsic::sqrt, types);
//                std::vector<Value *> args;
//                args.push_back(newVal);
//                newVal = builder->CreateCall(sqrtFun, args);
//                newVal = builder->CreateFPToUI(newVal, rhs->getType());
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}

std::vector<std::string>
UnsignedGreaterThanEqualToPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex,
                                        Module &M) {
    std::vector<std::string> results;
    getpredicate(instr);
    if (isMutateable(CmpInst::Predicate::ICMP_UGE, instr)) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_GREATER_THAN_EQUALTO));
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
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_UGE) {
        if (isMutationLocation(instr, &seglist, UNSIGNED_GREATER_THAN_EQUALTO)) {
            // substract 1 and give the new value to the instruction
            Value* rhs;
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            rhs = icmpinst->getOperand(1);
            Value *newVal;
            if (rhs->getType()->isPointerTy()){
                LLVMContext &llvmContext = M.getContext();
                auto int_type = IntegerType::get (llvmContext, 32);
                Value* indexList = ConstantInt::get(int_type, -8);
                newVal = builder->CreateGEP(rhs, indexList);
            }
            else if (rhs->getType()->isIntegerTy()){
                newVal = insertMutationFunctionCall(rhs, builder, M, "mutate_root_half_sub");
//                newVal = builder->CreateSub(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
            }
            icmpinst->setOperand(1, newVal);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}
//
//std::vector<std::string>
//UnsignedGreaterThanEqualToHalvedPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex,
//                                        Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_UGE, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_GREATER_THAN_EQUALTO_HALVED));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_UGE.
// * It changes one of the operators to cause an off-by one error.
// */
//bool UnsignedGreaterThanEqualToHalvedPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_UGE) {
//        if (isMutationLocation(instr, &seglist, UNSIGNED_GREATER_THAN_EQUALTO_HALVED)) {
//            // substract 1 and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, -8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateUDiv(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 2));
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}
//
//std::vector<std::string>
//UnsignedGreaterThanEqualToSqrtPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex,
//                                              Module &M) {
//    std::vector<std::string> results;
//    getpredicate(instr);
//    if (isMutateable(CmpInst::Predicate::ICMP_UGE, instr)) {
//        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_GREATER_THAN_EQUALTO_SQRT));
//    }
//    return results;
//}
//
///**
// * The mutator for ICMP_UGE.
// * It changes one of the operators to cause an off-by one error.
// */
//bool UnsignedGreaterThanEqualToSqrtPattern::mutate(
//        IRBuilder<>* builder,
//        IRBuilder<>* nextInstructionBuilder,
//        Instruction* instr,
//        std::mutex& builderMutex,
//        Module& M
//) {
//    auto* icmpinst = dyn_cast<ICmpInst>(instr);
//    auto predicate = icmpinst->getPredicate();
//    if (predicate == CmpInst::Predicate::ICMP_UGE) {
//        if (isMutationLocation(instr, &seglist, UNSIGNED_GREATER_THAN_EQUALTO_SQRT)) {
//            // substract 1 and give the new value to the instruction
//            Value* rhs;
//            builderMutex.lock();
//            auto segref = seglist;
//            addMutationFoundSignal(builder, M, segref["UID"]);
//            rhs = icmpinst->getOperand(1);
//            Value *newVal;
//            if (rhs->getType()->isPointerTy()){
//                LLVMContext &llvmContext = M.getContext();
//                auto int_type = IntegerType::get (llvmContext, 32);
//                Value* indexList = ConstantInt::get(int_type, -8);
//                newVal = builder->CreateGEP(rhs, indexList);
//            }
//            else if (rhs->getType()->isIntegerTy()){
//                newVal = builder->CreateLShr(rhs, builder->getIntN(rhs->getType()->getIntegerBitWidth(), 1));
//                newVal = builder->CreateUIToFP(newVal, Type::getDoubleTy(M.getContext()));
//                std::vector<Type *> types;
//                types.push_back(Type::getDoubleTy(M.getContext()));
//                types.push_back(Type::getDoubleTy(M.getContext()));
//                auto sqrtFun = Intrinsic::getDeclaration(&M, Intrinsic::sqrt, types);
//                std::vector<Value *> args;
//                args.push_back(newVal);
//                newVal = builder->CreateCall(sqrtFun, args);
//                newVal = builder->CreateFPToUI(newVal, rhs->getType());
//            }
//            icmpinst->setOperand(1, newVal);
//            builderMutex.unlock();
//            return true;
//        }
//    }
//    return false;
//}

std::vector<std::string>
SignedToUnsigned::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_SGT || predicate == CmpInst::Predicate::ICMP_SGE
    || predicate == CmpInst::Predicate::ICMP_SLT || predicate == CmpInst::Predicate::ICMP_SLE) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SIGNED_TO_UNSIGNED));
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
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_SGT || predicate == CmpInst::Predicate::ICMP_SGE
        || predicate == CmpInst::Predicate::ICMP_SLT || predicate == CmpInst::Predicate::ICMP_SLE) {
        std::vector<int> typelist {SIGNED_TO_UNSIGNED};
        if (isMutationLocation(instr, &seglist, &typelist)) {
            // change from signed to unsigned
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
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


std::vector<std::string>
UnsignedToSigned::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    getpredicate(instr);
    if (predicate == CmpInst::Predicate::ICMP_UGT || predicate == CmpInst::Predicate::ICMP_UGE
        || predicate == CmpInst::Predicate::ICMP_ULT || predicate == CmpInst::Predicate::ICMP_ULE) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, UNSIGNED_TO_SIGNED));
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
        Module& M
) {
    auto* icmpinst = dyn_cast<ICmpInst>(instr);
    auto predicate = icmpinst->getPredicate();
    if (predicate == CmpInst::Predicate::ICMP_UGT || predicate == CmpInst::Predicate::ICMP_UGE
        || predicate == CmpInst::Predicate::ICMP_ULT || predicate == CmpInst::Predicate::ICMP_ULE) {
        std::vector<int> typelist {UNSIGNED_TO_SIGNED};
        if (isMutationLocation(instr, &seglist, &typelist)) {
            // change from signed to unsigned
            builderMutex.lock();
            auto segref = seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
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