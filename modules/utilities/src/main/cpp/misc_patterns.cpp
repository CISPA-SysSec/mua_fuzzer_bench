#include "../public/pattern_lib.h"
#include "mutations.h"
#include "pattern_declarations.h"

std::vector<std::string>
FreeArgumentReturnPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    if (auto returnInst = dyn_cast<ReturnInst>(instr)) {
        const Function *outerFunction = returnInst->getFunction();
        for (auto op = outerFunction->arg_begin(); op != outerFunction->arg_end(); op++) {
            if (op->getType()->isPointerTy()) {
                json j;
                j["argnumber"] = op->getArgNo();
                results.push_back(getIdentifierString(instr, builder, builderMutex, M, FREE_FUNCTION_ARGUMENT, j));
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
        const Function *outerFunction = returnInst->getFunction();
        // llvm has only one exit point per function, hence checking for a return instruction and the function name is
        // sufficient; checking for the actual location might sometimes fail as the debug information might be missing
        if (isMutationLocation(instr, seglist, FREE_FUNCTION_ARGUMENT)) {

            builderMutex.lock();
            addMutationFoundSignal(builder, M, segref["UID"]);
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


std::vector<std::string>
CMPXCHGPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    if (dyn_cast<AtomicCmpXchgInst>(instr)){
        const std::string &funNameStdString = instr->getFunction()->getName().str();
        if (pthreadFoundFunctions.find(funNameStdString) == pthreadFoundFunctions.end()) { // function was not used before
            pthreadFoundFunctions.insert(funNameStdString);
            json j;
            j["funname"] = funNameStdString;
            results.push_back(getIdentifierString(instr, builder, builderMutex, M, ATOMIC_CMP_XCHG, j));
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
        addMutationFoundSignal(nextInstructionBuilder, M, segref["UID"]);
        nextInstructionBuilder->CreateInsertValue(instr, builder->getIntN(1, 1), (uint64_t) 1);
        builderMutex.unlock();
        return true;
    }
    return false;
}

std::vector<std::string>
ATOMICRMWPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    if (!foundAtomicRMW) { // atomicrmw was not found yet
        if (dyn_cast<AtomicRMWInst>(instr)) {
            results.push_back(getIdentifierString(instr, builder, builderMutex, M, ATOMICRMW_REPLACE));
            foundAtomicRMW = true;
        }
    }
    return results;
}


/**
 * If we have at least one atomicrmw instruction, we replace all atomicrmw with its non-atomic counterpart in a certain
 * function.
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
        auto mutated = convertAtomicBinOpToBinOp(rmw, seglist, nextInstructionBuilder, M);
        builderMutex.unlock();
        return mutated;
    }
    return false;
}

/**
 * TODO some versions of atomic instructions are not yet implemented
 * Takes the given atomic instruction and replaces it with its non-atomic counterpart.
 */
bool ATOMICRMWPattern::convertAtomicBinOpToBinOp(AtomicRMWInst* instr, json *seglist, IRBuilder<>* nextInstructionBuilder, Module& M) {
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
    auto segref = *seglist;
    addMutationFoundSignal(nextInstructionBuilder, M, segref["UID"]);
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


std::vector<std::string>
ShiftSwitch::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    if (dyn_cast<LShrOperator>(instr) || dyn_cast<AShrOperator>(instr)) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, SWITCH_SHIFT));
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
            auto segref = *seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            auto ashr = builder->CreateAShr(castedlshr->getOperand(0), castedlshr->getOperand(1));
            instr->replaceAllUsesWith(ashr);
            instr->removeFromParent();
            builderMutex.unlock();
            return true;
        } else {
            if (auto castedashr = dyn_cast<AShrOperator>(instr)) {
                builderMutex.lock();
                auto segref = *seglist;
                addMutationFoundSignal(builder, M, segref["UID"]);
                auto lshr = builder->CreateLShr(castedashr->getOperand(0), castedashr->getOperand(1));
                instr->replaceAllUsesWith(lshr);
                instr->removeFromParent();
                builderMutex.unlock();
                return true;
            }
        }
    }
    return false;
}


std::vector<std::string>
UnInitLocalVariables::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    if (auto allocation_instr = dyn_cast<AllocaInst>(instr)) {
        // We only store the location if the allocation is not a array type,
        // since array type allocation don't have any corresponding store to mutate on.
        if (!allocation_instr->getAllocatedType()->isArrayTy()){
            json j;
            auto surroundingFunction = instr->getFunction()->getName().str();
            j["funname"] = surroundingFunction;
            std::string instructionString;
            llvm::raw_string_ostream os(instructionString);
            instr->print(os);
            j["instr"] = os.str();
            results.push_back(getIdentifierString_unsignaled(instr, DELETE_LOCAL_STORE, j));
            std::vector<const User*> users;
            for(auto user : instr->users()){ // user is of type User*
                users.push_back(user);
            }
            // using the c++11 vector range iterator does not stop for some reason, so we use iteration by index
            for(std::vector<const User*>::size_type i = 0; i != users.size(); i++){  // user is of type User*
                auto user = users[i];
                if (user) {
                    if (auto instrUser = (StoreInst*)dyn_cast<StoreInst>(user)){
                        to_delete.insert(instrUser);
                        BasicBlock::iterator itr_bb(instrUser);
                        IRBuilder<> userBuilder(instrUser->getParent(), itr_bb);
                          //PatterIDCounter - 1 since it was already increased in getIdentifierString_unsignaled
                        addMutationFoundSignal(&userBuilder, M, PatternIDCounter - 1);
                    }
                }
            }
        }
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
            for(auto user : instr->users()){  // user is of type User*
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
                addMutationFoundSignal(builder, M, segref["UID"]);
                store->removeFromParent();
                builderMutex.unlock();
                return true;
            }
        }
    }
    return false;
}

/*
 * The find method for ICMP_EQ.
 * A previous load instruction needs to be changed into a store instruction.
 * We consider only the load instructions which
 * 1) has an user that is ICmpInst with ICMP_EQ predicate
 * 2) is the first operand in the ICmpInst (to eliminate double counting in case
 * second operand is also a load instruction)
 */
std::vector<std::string>
CompareEqualToPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    std::vector<std::string> results;
    if (auto loadInstr = dyn_cast<LoadInst>(instr)) {
        for(auto user : loadInstr->users()){  // user is of type User*
            if (auto iCmpInstr = dyn_cast<ICmpInst>(user)){
                //we only note one mutationlocation. The second check ensures
                //this in case the RHS of the comparision is also a variable.
                if (iCmpInstr->getPredicate() == CmpInst::Predicate::ICMP_EQ &&
                    iCmpInstr->getOperand(0) == loadInstr){
                    json j;
                    std::string instructionString;
                    llvm::raw_string_ostream os(instructionString);
                    iCmpInstr->print(os);
                    j["ICmpinstr"] = os.str();
                    results.push_back(getIdentifierString(instr,  builder, builderMutex, M, COMPARE_EQUAL_TO, j));
                }
            }
        }
    }
    return results;
}

/*
 * The mutator for ICMP_EQ.
 * A previous load instruction needs to be changed into a store instruction.
 * Which is why this isn't a ICmpPattern subclass.
 * It changes the "==" sign to "=" in a comparision.
 */
bool CompareEqualToPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto segref = *seglist;
    if (isMutationLocation(instr, seglist, COMPARE_EQUAL_TO)) {
        if (auto loadInstr =  dyn_cast<LoadInst>(instr)){
            for(auto user : loadInstr->users()){  // user is of type User*
                if (auto iCmpInstr = dyn_cast<ICmpInst>(user)){
                    //This check ensures we don't consider mutation a second time
                    //for the second load (in case RHS is also a variable)
                    std::string instructionString;
                    llvm::raw_string_ostream os(instructionString);
                    iCmpInstr->print(os);
                    if (segref["additionalInfo"]["ICmpinstr"] == os.str()){
                        builderMutex.lock();
                        addMutationFoundSignal(nextInstructionBuilder, M, segref["UID"]);
                        new StoreInst(iCmpInstr->getOperand(1), loadInstr->getPointerOperand(), iCmpInstr);
                        //This works for both integers and pointers.
                        auto newVal = Constant::getNullValue(iCmpInstr->getOperand(0)->getType());
                        iCmpInstr->setOperand(0, iCmpInstr->getOperand(1));
                        iCmpInstr->setPredicate(CmpInst::Predicate::ICMP_NE);
                        iCmpInstr->setOperand(1, newVal);
                        if (loadInstr->user_empty()) {
                            // we only remove the load instruction if no other users exist
                            loadInstr->removeFromParent();
                        }
                        builderMutex.unlock();
                        return true;
                    }
                }
            }
        }
    }
    return false;
}