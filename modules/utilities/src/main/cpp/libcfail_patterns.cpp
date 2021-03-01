#include "../public/pattern_lib.h"
#include "mutations.h"
#include "pattern_declarations.h"

std::vector<std::string> LibCFailPattern::findConcreteFunction(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module& M, const std::string& funName, int patternID) {
    std::vector<std::string> results;
    getfunNameString(instr);
    if (funNameString.find(funName) != std::string::npos) {
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