#include "../public/pattern_lib.h"
#include "mutations.h"
#include "pattern_declarations.h"

std::vector<std::string> LibCFailPattern::findConcreteFunction(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module& M, const std::string& funName, int patternID) {
    std::vector<std::string> results;
    getfunNameString(instr);
    // TODO in some cases the function name is different from the C-code function name, e.g. we might have 01_inet_addr instead of inet_addr in the code
    //  in that case the function might not be found and we need to be more generous when looking for it
    // do an equals check here as for functions like printf there might be functions that are similarly named (e.g. snprintf)
    if (funNameString.str() == funName) {
        results.push_back(getIdentifierString(instr, builder, builderMutex, M, patternID));
    }
    return results;
}

bool LibCFailPattern::concreteMutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M,
        int patternID,
        int returnValueForFail
) {
    auto segref = *seglist;
    if (isMutationLocation(instr, seglist, patternID)) {  // no check for concrete mutation location as the alloca instructions are added by LLVM
        // get the concrete value to delete by checkin if the instruction string matches and then saving the value
        addMutationFoundSignal(builder, M, segref["UID"]);
        for(auto user : instr->users()){  // user is of type User*
            if (auto instrUser = dyn_cast<CmpInst>(user)){
                std::string strin;
                llvm::raw_string_ostream oss(strin);
                user->print(oss);
                foundCompareUses.insert(instrUser);
            }
        }
        // replace with some failing call, replacing the return value with a constant might actually be sufficient
        // the constant needs to be the correct failure code for the called function, so it should be given as an argument to concreteMutate
        instr->replaceAllUsesWith(builder->getInt32(returnValueForFail));
        instr->removeFromParent();
        builderMutex.unlock();
        return false;
    }
    auto cmpInst = dyn_cast<CmpInst>(instr);
    // if the operand of the cmpInst operation matches the local variable, we delete the cmpInst operation
    if (cmpInst) {
        if (foundCompareUses.find(cmpInst) != foundCompareUses.end()) {
            std::cout << "found cmp location!" << "\n";
            builderMutex.lock();
            // take the result of the comparison and flip it by checking it for equality to false
            auto negate = nextInstructionBuilder->CreateCmp(CmpInst::Predicate::ICMP_EQ, cmpInst, builder->getInt1(false));
            // then replace all uses of the result of the compare instruction with the negated value
            cmpInst->replaceAllUsesWith(negate);
            builderMutex.unlock();
            return true;
        }
    }
    return false;
}

/**
 * Replaces all uses of the function return value to the failure value. Also removes the function call from the corpus
 * as a fail of the function call should be simulated.
 * Furthermore, the comparison instructions are flipped, s.t. on failure the "correct" path is taken, i.e. we simulate
 * a missing check for the error return value.
 */
bool INetAddrFailPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    return concreteMutate(builder, nextInstructionBuilder, instr, builderMutex, seglist, M, INET_ADDR_FAIL_WITHOUTCHECK, -1);
}


std::vector<std::string>
INetAddrFailPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    return findConcreteFunction(instr, builder, builderMutex, M, "inet_addr", INET_ADDR_FAIL_WITHOUTCHECK);
}

std::vector<std::string>
PrintfPattern::find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) {
    return findConcreteFunction(instr, builder, builderMutex, M, "printf", PRINTF);
}

bool PrintfPattern::mutate(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M
) {
    auto* callInstr = dyn_cast<CallInst>(instr);
    if (callInstr){
        if (isMutationLocation(instr, seglist, PRINTF)){
            builderMutex.lock();
            auto segref = *seglist;
            addMutationFoundSignal(builder, M, segref["UID"]);
            std::vector<Value*> cfn_args;
            for (int i =0; i<callInstr->getNumArgOperands(); i++){
                cfn_args.push_back(callInstr->getArgOperand(i));
            }
            auto signalFunction = M.getFunction("mutate_printf_string");
            builder->CreateCall(signalFunction, cfn_args);
            callInstr->removeFromParent();
            builderMutex.unlock();
            return true;
        }

    }
    return false;
}