//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/mutator_lib.h"
#include "mutations.h"


bool isMutationDebugLoc(const Instruction *instr, const json &segref);

bool isMutationLocation(Instruction* instr, json *seglist, int type) {
    auto segref = *seglist;
    if (segref["type"] == type) {
        return isMutationDebugLoc(instr, segref);
    } else {
        return false;
    }
}

bool isMutationLocation(Instruction* instr, json *seglist, const std::vector<int>* types) {
    auto segref = *seglist;
    int givenType = segref["type"];
    for (auto type : *types) {
        if (givenType == type) {
            return isMutationDebugLoc(instr, segref);
        }
    }
    return false;
}

bool isMutationDebugLoc(const Instruction *instr, const json &segref) {
    const DebugLoc &debugInfo = instr->getDebugLoc();
    if (debugInfo) {
        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        uint64_t line = debugInfo->getLine();
        uint64_t column = debugInfo->getColumn();
        return segref["directory"] == directory
               && segref["filePath"] == filePath
               && segref["line"] == line
               && segref["column"] == column;
    } else {
        return false; // if the debug loc does not exist, we cannot do a mutation
    }
}

/**
 * On all function returns it frees all arguments that are pointers, for each argument a unique mutant is created.
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @param M
 * @return
 */
bool mutateFreeArgumentReturn(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto segref = *seglist;
    if (auto returnInst = dyn_cast<ReturnInst>(instr)) {
        if (isMutationLocation(instr, seglist, FREE_FUNCTION_ARGUMENT)) {

            builderMutex.lock();
            LLVMContext &llvmContext = M.getContext();
            // first bitcast to i8* as this is the type free expects
            std::string extra_arg = segref["additionalInfo"]["extra_arg"];
            auto funArg = returnInst->getFunction()->getArg(std::stoi(extra_arg));
            auto bitcasted = builder->CreateBitCast(funArg, Type::getInt8PtrTy(llvmContext));
            auto args = std::vector<Value*>();
            args.push_back(bitcasted);

            // add free to the environment and then add it to the code
            auto freeFun = M.getOrInsertFunction("free", Type::getVoidTy(llvmContext), Type::getInt8PtrTy(llvmContext));
            builder->CreateCall(freeFun, args);
            builderMutex.unlock();

            return true;
        }
    }
    return false;
}

/**
 * For the given function it replaces all locks and unlocks in the function.
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @param callinst
 * @return
 */
bool mutatePThread(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        CallInst* callinst
) {
    auto funNameString = callinst->getCalledFunction()->getName();
    auto surroundingFunction = instr->getFunction()->getName().str();
    auto segref = *seglist;
    // we need a more fuzzy match here, the concrete location is not important, only the function
    if (segref["type"] == PTHREAD_MUTEX
        && surroundingFunction == segref["additionalInfo"]["extra_arg"]
        && (funNameString.find("pthread_mutex_lock") != std::string::npos
        || funNameString.find("pthread_mutex_unlock") != std::string::npos)
    ){
        builderMutex.lock();
        // the return value of the locking could be used somewhere, hence we need to make sure that this value still exists and simulates a successful lock
        instr->replaceAllUsesWith(builder->getInt32(1));
        // then we can remove the instruction from the parent
        instr->removeFromParent();
        builderMutex.unlock();
        return true;
    }
    return false;
}

/**
 * For the given function it takes the return value of the compare exchange and replaces the compare result with true.
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @return
 */
bool mutateCMPXCHG(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist
) {
    auto surroundingFunction = instr->getFunction()->getName().str();
    auto segref = *seglist;
    // we need a more fuzzy match here, the concrete location is not important, only the function
    if (segref["type"] == ATOMIC_CMP_XCHG
        && surroundingFunction == segref["additionalInfo"]["extra_arg"]
        && dyn_cast<AtomicCmpXchgInst>(instr))
    {
        builderMutex.lock();
        // we leave the atomicxchg in but always return 1, hence we emulate an always successful exchange
//        auto returnVal = instr->getOperand(0);
        nextInstructionBuilder->CreateInsertValue(instr, builder->getIntN(1, 1), (uint64_t) 1);
        builderMutex.unlock();
        return true;
    }
    return false;
}

/**
 * TODO some versions of atomic instructions are not yet implemented
 * Takes the given atomic instruction and replaces it with its non-atomic counterpart.
 * @param instr
 * @param nextInstructionBuilder
 * @return
 */
bool convertAtomicBinOpToBinOp(AtomicRMWInst* instr, IRBuilder<>* nextInstructionBuilder) {
    auto operation = instr->getOperation();
    Instruction::BinaryOps operand = llvm::Instruction::BinaryOpsBegin;
    switch (operation) {
        case AtomicRMWInst::Xchg:
        case AtomicRMWInst::Nand:
        case AtomicRMWInst::Max:
        case AtomicRMWInst::Min:
        case AtomicRMWInst::UMax:
        case AtomicRMWInst::UMin:
            return false; // TODO in future we can populate this as well
        case AtomicRMWInst::Add:
        {
            operand = Instruction::BinaryOps::Add;
            break;
        }
        case AtomicRMWInst::Sub:
        {
            operand = Instruction::BinaryOps::Sub;
            break;
        }
        case AtomicRMWInst::And:
        {
            operand = Instruction::BinaryOps::And;
            break;
        }
        case AtomicRMWInst::Or:
        {
            operand = Instruction::BinaryOps::Or;
            break;
        }
        case AtomicRMWInst::Xor:
        {
            operand = Instruction::BinaryOps::Xor;
            break;
        }
        case AtomicRMWInst::FAdd:
        {
            operand = Instruction::BinaryOps::FAdd;
            break;
        }
        case AtomicRMWInst::FSub:
        {
            operand = Instruction::BinaryOps::FSub;
            break;
        }
        case AtomicRMWInst::BAD_BINOP:
            return false;
    }

    // generic code for most binops: first load the lhs, then create a standard binop, then replace values and remove
    // old atomic version
    auto loadResult = nextInstructionBuilder->CreateLoad(instr->getOperand(0));
    auto newinst = nextInstructionBuilder->CreateBinOp(
            operand,
            loadResult,
            instr->getOperand(1)
    );
    instr->replaceAllUsesWith(newinst);
    instr->removeFromParent();
    return true;
}

/**
 * If we have at least one atomicrmw instruction, we replace the atomicrmw with its non-atomic counterpart.
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @return
 */
bool mutateATOMICRMW(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist
) {
    auto surroundingFunction = instr->getFunction()->getName().str();
    auto segref = *seglist;
    // we need a more fuzzy match here, the concrete location is not important, only if we mutate the atomicrmw instruction
    auto rmw = dyn_cast<AtomicRMWInst>(instr);
    if (segref["type"] == ATOMICRMW_REPLACE && rmw)
    {
        builderMutex.lock();
        // we replace the atomicrmw with its non-atomic counterpart
        auto mutated = convertAtomicBinOpToBinOp(rmw, nextInstructionBuilder);
        builderMutex.unlock();
        return mutated;
    }
    return false;
}

/**
 * On malloc it allocates one byte less memory.
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @param callinst
 * @return
 */
bool mutateMalloc(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        CallInst* callinst
) {
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.find("malloc") != std::string::npos) {
        if (isMutationLocation(instr, seglist, MALLOC)) {
            // substract 1 and give the new value to malloc
            Value* lhs;
            lhs = callinst->getArgOperand(0);
            builderMutex.lock();
            auto newVal = builder->CreateAdd(lhs, builder->getInt64(-1));
            builderMutex.unlock();
            callinst->setOperand(0, newVal);
            return true;
        }
    }
    return false;
}

/**
 * On fgets it allows to read more bytes than intended by the developer (concretely if X bytes should have been
 * read, (X+1)*5 bytes are read).
 * @param builder
 * @param nextInstructionBuilder
 * @param instr
 * @param builderMutex
 * @param seglist
 * @param callinst
 * @return
 */
bool mutateFGets(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        CallInst* callinst
) {
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.find("fgets") != std::string::npos) {
        if (isMutationLocation(instr, seglist, FGETS_MATCH_BUFFER_SIZE)) {
            // add 1 to original value, multiply this new value by 5 and then
            // give the value to fgets
            Value* lhs;
            lhs = callinst->getArgOperand(1);
            builderMutex.lock();
            auto newVal = builder->CreateAdd(lhs, builder->getInt64(1));
            newVal = builder->CreateMul(newVal, builder->getInt64(5));
            builderMutex.unlock();
            callinst->setOperand(1, newVal);
            return true;
        }
    }
    return false;
}

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
bool mutateGreaterThan(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        ICmpInst* icmpinst
) {
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
bool mutateLessThan(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        ICmpInst* icmpinst
) {
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



/**
     * Mutate the given function call if a mutation pattern exists for the function.
     * @param builder the builder to add instruction in front of the call
     * @param nextInstructionBuilder the builder to add instructions after the call
     * @param instr the instruction to mutate (i.e. the function call)
     * @param seglist the list of mutation locations, each mutator can decide upon the list if it should mutate the loc
     * @return
     */
bool mutatePattern(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
)
{
    // TODO until further refactoring put call instruction mutations in here
    // TODO in future we should have one abstract class from which concrete mutators should inherit
    // TODO we just register the mutators here and call them, same for the pattern finder
    auto mutated = false;
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        auto calledFun = callinst->getCalledFunction();
        if (calledFun) {
            mutated |= mutateMalloc(builder, nextInstructionBuilder, instr, builderMutex, seglist, callinst);
            mutated |= mutateFGets(builder, nextInstructionBuilder, instr, builderMutex, seglist, callinst);
            mutated |= mutatePThread(builder, nextInstructionBuilder, instr, builderMutex, seglist, callinst);
        }
    }
    else if (auto* cmpinst = dyn_cast<ICmpInst>(instr)){
        mutated |= mutateGreaterThan(builder, nextInstructionBuilder, instr, builderMutex, seglist, cmpinst);
        mutated |= mutateLessThan(builder, nextInstructionBuilder, instr, builderMutex, seglist, cmpinst);
    } else {
        mutated |= mutateFreeArgumentReturn(builder, nextInstructionBuilder, instr, builderMutex, seglist, M);
        mutated |= mutateCMPXCHG(builder, nextInstructionBuilder, instr, builderMutex, seglist);
        mutated |= mutateATOMICRMW(builder, nextInstructionBuilder, instr, builderMutex, seglist);
    }
    return mutated;
}