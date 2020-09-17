//
// Created by Björn Mathis on 11.09.20.
//

#include <iostream>
#include "../public/mutator_lib.h"
#include "mutations.h"


bool mutateMalloc(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        std::vector<std::string>* seglist,
        CallInst* callinst
) {
    auto segref = *seglist;
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.find("malloc") != std::string::npos) {
        const llvm::DebugLoc &debugInfo = instr->getDebugLoc();
        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        int line = debugInfo->getLine();
        int column = debugInfo->getColumn();

        if (segref[0] == directory
            && segref[1] == filePath
            && std::stoi(segref[2]) == line
            && std::stoi(segref[3]) == column
            && std::stoi(segref[4]) == MALLOC) {
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

bool mutateFGets(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        std::vector<std::string>* seglist,
        CallInst* callinst
) {
    auto segref = *seglist;
    auto funNameString = callinst->getCalledFunction()->getName();
    if (funNameString.find("fgets") != std::string::npos) {
        const llvm::DebugLoc &debugInfo = instr->getDebugLoc();
        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        int line = debugInfo->getLine();
        int column = debugInfo->getColumn();

        if (segref[0] == directory
            && segref[1] == filePath
            && std::stoi(segref[2]) == line
            && std::stoi(segref[3]) == column
            && std::stoi(segref[4]) == FGETS_MATCH_BUFFER_SIZE) {
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


// The mutator for both ICMP_SGT, ICMP_SGE will be the same
bool mutateGreaterThan(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        std::vector<std::string>* seglist,
        ICmpInst* icmpinst
) {
    auto segref = *seglist;
    auto predicate = icmpinst->getPredicate();
    if (predicate == 38 || predicate == 39) {
        const llvm::DebugLoc &debugInfo = instr->getDebugLoc();
        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        int line = debugInfo->getLine();
        int column = debugInfo->getColumn();

        if (segref[0] == directory
            && segref[1] == filePath
            && std::stoi(segref[2]) == line
            && std::stoi(segref[3]) == column
            && (std::stoi(segref[4]) == SIGNED_GREATER_THAN ||
                std::stoi(segref[4]) == SIGNED_GREATER_THAN_EQUALTO )) {
            // substract 1 and give the new value to the instruction
            Value* rhs;
            rhs = icmpinst->getOperand(1);
            builderMutex.lock();
            auto newVal = builder->CreateSub(rhs, builder->getInt64(1));
            builderMutex.unlock();
            icmpinst->setOperand(1, newVal);
            return true;
        }
    }
    return false;
}

// The mutator for both ICMP_SLT, ICMP_SLE will be the same
bool mutateLessThan(
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        std::vector<std::string>* seglist,
        ICmpInst* icmpinst
) {
    auto segref = *seglist;
    auto predicate = icmpinst->getPredicate();
    if (predicate == 40 || predicate == 41) {
        const llvm::DebugLoc &debugInfo = instr->getDebugLoc();
        std::string directory = debugInfo->getDirectory().str();
        std::string filePath = debugInfo->getFilename().str();
        int line = debugInfo->getLine();
        int column = debugInfo->getColumn();

        if (segref[0] == directory
            && segref[1] == filePath
            && std::stoi(segref[2]) == line
            && std::stoi(segref[3]) == column
            && (std::stoi(segref[4]) == SIGNED_LESS_THAN ||
                std::stoi(segref[4]) == SIGNED_LESS_THAN_EQUALTO )) {
            // add 2 and give the new value to the instruction
            Value* rhs;
            rhs = icmpinst->getOperand(1);
            builderMutex.lock();
            auto newVal = builder->CreateAdd(rhs, builder->getInt64(1));
            newVal = builder->CreateMul(newVal, builder->getInt64(2));
            builderMutex.unlock();
            icmpinst->setOperand(1, newVal);
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
        std::vector<std::string>* seglist
)
{
    // TODO until further refactoring put call instruction mutations in here
    // TODO in future we should have one abstract class from which concrete mutators should inherit
    // TODO we just register the mutators here and call them, same for the pattern finder
    auto mutated = false;
    if (auto* callinst = dyn_cast<CallInst>(instr)) {
        mutated |= mutateMalloc(builder, nextInstructionBuilder, instr, builderMutex, seglist, callinst);
        mutated |= mutateFGets(builder, nextInstructionBuilder, instr, builderMutex, seglist, callinst);
        return mutated;
    }
    else if (auto* cmpinst = dyn_cast<ICmpInst>(instr)){
        mutated |= mutateGreaterThan(builder, nextInstructionBuilder, instr, builderMutex, seglist, cmpinst);
        mutated |= mutateLessThan(builder, nextInstructionBuilder, instr, builderMutex, seglist, cmpinst);
    }
    return true;
}