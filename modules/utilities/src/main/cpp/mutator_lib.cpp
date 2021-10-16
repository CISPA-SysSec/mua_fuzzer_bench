//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/mutator_lib.h"
#include "pattern_list.h"


bool Pattern::isMutationLocation(Instruction* instr, json *seglist, int type) {
    auto segref = *seglist;
    if (segref["type"] == type) {
        return isMutationDebugLoc(instr, segref);
    } else {
        return false;
    }
}

bool Pattern::isMutationLocation(Instruction* instr, json *seglist, const std::vector<int>* types) {
    auto segref = *seglist;
    int givenType = segref["type"];
    for (auto type : *types) {
        if (givenType == type) {
            return isMutationDebugLoc(instr, segref);
        }
    }
    return false;
}

bool Pattern::isMutationDebugLoc(const Instruction *instr, const json &segref) {
    const DebugLoc &debugInfo = instr->getDebugLoc();
    if (debugInfo) {
        //
        auto surroundingFunction = instr->getFunction()->getName().str();
        if (segref["funname"] != surroundingFunction) {
            // shortcut for faster failing if the function is not the one we are looking for
            return false;
        }
        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        uint64_t line = debugInfo->getLine();
        uint64_t column = debugInfo->getColumn();

        std::string instructionString;
        llvm::raw_string_ostream os(instructionString);
        instr->print(os);
        return segref["directory"] == directory
               && segref["filePath"] == filePath
               && segref["line"] == line
               && segref["column"] == column
               && segref["instr"] == os.str();
    } else {
        // as a fallback try to just use funname and instr
        auto surroundingFunction = instr->getFunction()->getName().str();
        if (segref["funname"] != surroundingFunction) {
            // shortcut for faster failing if the function is not the one we are looking for
            return false;
        }
        std::string instructionString;
        llvm::raw_string_ostream os(instructionString);
        instr->print(os);
        return segref["instr"] == os.str();
    }
}

/**
 * A helper function that should be called whenever a mutation is done to signal that the mutation was triggered during
 * runtime.
 * @param builder
 * @param M
 */
void Pattern::addMutationFoundSignal(IRBuilder<> *builder, Module& M, int UID) {
        auto args = std::vector<Value*>();
        args.push_back(builder->getInt64(UID));
        auto signalFunction = M.getFunction("signal_triggered_mutation");
        builder->CreateCall(signalFunction, args);
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
        Module& M
)
{
    auto mutated = false;
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        auto calledFun = callinst->getCalledFunction();
        if (calledFun) {
            for (auto &mutator : CallInstPatterns){
                mutated |= mutator->mutate(builder, nextInstructionBuilder, instr, builderMutex, M);
                if (mutated) break;
            }
        }
    }
    else if (dyn_cast<ICmpInst>(instr)){
        for (auto &mutator : ICmpInstPatterns){
                mutated |= mutator->mutate(builder, nextInstructionBuilder, instr, builderMutex, M);
                if (mutated) break;
        }
    } else {
        for (auto &mutator : MiscInstPatterns){
                mutated |= mutator->mutate(builder, nextInstructionBuilder, instr, builderMutex, M);
                if (mutated) break; //making sure that one instruction is only altered once, and will not cause crashes
        }
    }
    return mutated;
}

void insertMutationApiFunctions(Module& M, bool cpp) {
    LLVMContext &llvmContext = M.getContext();
    M.getOrInsertFunction("signal_triggered_mutation", Type::getVoidTy(llvmContext), Type::getInt64Ty(llvmContext));

    std::vector<Type*> mutate_printf_args(1, Type::getInt8PtrTy(llvmContext));
    M.getOrInsertFunction("mutate_printf_string", FunctionType::get(Type::getInt32Ty(llvmContext),  mutate_printf_args, true));

    // 2 char* for sprintf. first for *str, second for *format in int sprintf(char *str, const char *format, ...);
    std::vector<Type*> mutate_sprintf_args(2, Type::getInt8PtrTy(llvmContext));
    M.getOrInsertFunction("mutate_sprintf_string", FunctionType::get(Type::getInt32Ty(llvmContext),  mutate_sprintf_args, true));

    std::vector<Type*> mutate_snprintf_args;
    mutate_snprintf_args.push_back(Type::getInt8PtrTy(llvmContext));
    int bitsize = sizeof(size_t) *8;
    mutate_snprintf_args.push_back(Type::getIntNTy(llvmContext, bitsize));
    mutate_snprintf_args.push_back(Type::getInt8PtrTy(llvmContext));
    M.getOrInsertFunction("mutate_snprintf_string", FunctionType::get(Type::getInt32Ty(llvmContext),  mutate_snprintf_args, true));

    if (cpp){
        M.getOrInsertFunction("mutate_delete", Type::getVoidTy(llvmContext), Type::getInt8PtrTy(llvmContext));
    }
}