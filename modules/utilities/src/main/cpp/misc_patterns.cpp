#include "../public/pattern_lib.h"
#include "mutations.h"
#include "pattern_declarations.h"

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

/**
 * On all function returns it frees all arguments that are pointers, for each argument a unique mutant is created.
 */
bool FreeArgumentReturnPattern::mutate(
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


/**
 * For the given function it takes the return value of the compare exchange and replaces the compare result with true.
 */
bool CMPXCHGPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
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


/**
 * If we have at least one atomicrmw instruction, we replace the atomicrmw with its non-atomic counterpart.
 */
bool ATOMICRMWPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
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
 * TODO some versions of atomic instructions are not yet implemented
 * Takes the given atomic instruction and replaces it with its non-atomic counterpart.
 */
bool ATOMICRMWPattern::convertAtomicBinOpToBinOp(AtomicRMWInst* instr, IRBuilder<>* nextInstructionBuilder) {
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
    // TODO fix and re-enable (issue #8)
//    instr->removeFromParent();
    return true;
}


std::vector<std::string> ShiftSwitch::find(const Instruction *instr) {
    std::vector<std::string> results;
    if (dyn_cast<LShrOperator>(instr) || dyn_cast<LShrOperator>(instr)) {
        results.push_back(getIdentifierString(instr, SWITCH_SHIFT));
    }
    return results;
}


/**
 * Replaces an arithmetic shift with a logical shift and vice versa.
 */
bool ShiftSwitch::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    if (isMutationLocation(instr, seglist, SWITCH_SHIFT)) {
        if (auto castedlshr = dyn_cast<LShrOperator>(instr)) {
            builderMutex.lock();
            auto ashr = builder->CreateAShr(castedlshr->getOperand(0), castedlshr->getOperand(1));
            instr->replaceAllUsesWith(ashr);
            // TODO fix and re-enable (issue #8)
//            instr->removeFromParent();
            builderMutex.unlock();
            return true;
        } else {
            if (auto castedashr = dyn_cast<AShrOperator>(instr)) {
                builderMutex.lock();
                auto lshr = builder->CreateLShr(castedashr->getOperand(0), castedashr->getOperand(1));
                instr->replaceAllUsesWith(lshr);
                // TODO fix and re-enable (issue #8)
//                instr->removeFromParent();
                builderMutex.unlock();
                return true;
            }
        }
    }
    return false;
}