#include "../public/pattern_lib.h"
#include "mutations.h"
#include "pattern_declarations.h"

std::vector<std::string> FreeArgumentReturnPattern::find(const Instruction *instr) {
    std::vector<std::string> results;
    if (auto returnInst = dyn_cast<ReturnInst>(instr)) {
        const Function *outerFunction = returnInst->getFunction();
        for (auto op = outerFunction->arg_begin(); op != outerFunction->arg_end(); op++) {
            if (op->getType()->isPointerTy()) {
                json j;
                j["argnumber"] = op->getArgNo();
                results.push_back(getIdentifierString(instr, FREE_FUNCTION_ARGUMENT, j));
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
            addMutationFoundSignal(builder, M);
            LLVMContext &llvmContext = M.getContext();
            // first bitcast to i8* as this is the type free expects
            int extra_arg = segref["additionalInfo"]["argnumber"];
            auto funArg = returnInst->getFunction()->getArg(extra_arg);
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
    if (dyn_cast<AtomicCmpXchgInst>(instr)){
        const std::string &funNameStdString = instr->getFunction()->getName().str();
        if (pthreadFoundFunctions.find(funNameStdString) == pthreadFoundFunctions.end()) { // function was not used before
            pthreadFoundFunctions.insert(funNameStdString);
            json j;
            j["funname"] = funNameStdString;
            results.push_back(getIdentifierString(instr, ATOMIC_CMP_XCHG, j));
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
        && surroundingFunction == segref["additionalInfo"]["funname"]
        && dyn_cast<AtomicCmpXchgInst>(instr))
    {
        builderMutex.lock();
        // we leave the atomicxchg in but always return 1, hence we emulate an always successful exchange
//        auto returnVal = instr->getOperand(0);
        addMutationFoundSignal(nextInstructionBuilder, M);
        nextInstructionBuilder->CreateInsertValue(instr, builder->getIntN(1, 1), (uint64_t) 1);
        builderMutex.unlock();
        return true;
    }
    return false;
}

std::vector<std::string> ATOMICRMWPattern::find(const Instruction *instr) {
    std::vector<std::string> results;
    if (!foundAtomicRMW) { // atomicrmw was not found yet
        if (dyn_cast<AtomicRMWInst>(instr)) {
            results.push_back(getIdentifierString(instr, ATOMICRMW_REPLACE));
            foundAtomicRMW = true;
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
        auto mutated = convertAtomicBinOpToBinOp(rmw, nextInstructionBuilder, M);
        builderMutex.unlock();
        return mutated;
    }
    return false;
}

/**
 * TODO some versions of atomic instructions are not yet implemented
 * Takes the given atomic instruction and replaces it with its non-atomic counterpart.
 */
bool ATOMICRMWPattern::convertAtomicBinOpToBinOp(AtomicRMWInst* instr, IRBuilder<>* nextInstructionBuilder, Module& M) {
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
    addMutationFoundSignal(nextInstructionBuilder, M);
    instr->replaceAllUsesWith(newinst);
    instr->removeFromParent();
    return true;
}


std::vector<std::string> ShiftSwitch::find(const Instruction *instr) {
    std::vector<std::string> results;
    if (dyn_cast<LShrOperator>(instr) || dyn_cast<AShrOperator>(instr)) {
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
            addMutationFoundSignal(builder, M);
            auto ashr = builder->CreateAShr(castedlshr->getOperand(0), castedlshr->getOperand(1));
            instr->replaceAllUsesWith(ashr);
            instr->removeFromParent();
            builderMutex.unlock();
            return true;
        } else if (auto castedashr = dyn_cast<AShrOperator>(instr)) {
                builderMutex.lock();
                addMutationFoundSignal(builder, M);
                auto lshr = builder->CreateLShr(castedashr->getOperand(0), castedashr->getOperand(1));
                instr->replaceAllUsesWith(lshr);
                instr->removeFromParent();
                builderMutex.unlock();
                return true;
        }
    }
    return false;
}


std::vector<std::string> UnInitLocalVariables::find(const Instruction *instr) {
    std::vector<std::string> results;
    if (dyn_cast<AllocaInst>(instr)) {
        json j;
        auto surroundingFunction = instr->getFunction()->getName().str();
        j["funname"] = surroundingFunction;
        std::string instructionString;
        llvm::raw_string_ostream os(instructionString);
        instr->print(os);
        j["instr"] = os.str();
        results.push_back(getIdentifierString(instr, DELETE_LOCAL_STORE, j));
    }
    return results;
}


/**
 * Replaces all stores on a local variable in one function.
 */
bool UnInitLocalVariables::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto segref = *seglist;
    if (segref["type"] != DELETE_LOCAL_STORE) {
        return false;
    }
    Function *pFunction = instr->getFunction();
    if (!pFunction) {
        return false;
    }
    auto surroundingFunction = pFunction->getName();
    if (segref["additionalInfo"]["funname"] == surroundingFunction.str()) {  // no check for concrete mutation location as the alloca instructions are added by LLVM
        // get the concrete value to delete by checkin if the instruction string matches and then saving the value
        std::string instructionString;
        llvm::raw_string_ostream os(instructionString);
        instr->print(os);
        if (segref["additionalInfo"]["instr"] == os.str()) {
            for(auto user : instr->users()){  // U is of type User*
                if (auto instrUser = dyn_cast<StoreInst>(user)){
                    std::string strin;
                    llvm::raw_string_ostream oss(strin);
                    user->print(oss);
                    to_delete.insert(instrUser);
                }
            }
            return false;
        }
        auto store = dyn_cast<StoreInst>(instr);
        // if the operand of the store operation matches the local variable, we delete the store operation
        if (store) {
            if (to_delete.find(store) != to_delete.end()) {
                builderMutex.lock();
                addMutationFoundSignal(builder, M);
                store->removeFromParent();
                builderMutex.unlock();
                return true;
            }
        }
    }
    return false;
}