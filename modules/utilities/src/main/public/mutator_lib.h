//
// Created by Björn Mathis on 11.09.20.
//

#ifndef LLVM_MUTATION_TOOL_MUTATOR_LIB_H
#define LLVM_MUTATION_TOOL_MUTATOR_LIB_H



#include <llvm/Pass.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <../dependencies/json.hpp>

using json = nlohmann::json;
using namespace llvm;

#define ADDITIONAL_INFORMATION_START = 5  //the index of the first additional information argument, in future we should have some json format or so which makes this unnecessary

class PatternMutator;
void populateMutatorVectors();

bool mutatePattern(
    IRBuilder<>* builder,
    IRBuilder<>* nextInstructionBuilder,
    Instruction* instr,
    std::mutex& builderMutex,
    json *seglist,
    Module& M
);

// The most abstract base class
class PatternMutator
{
    public:
    // Pure Virtual Function
    virtual bool mutate (
        IRBuilder<>* builder,
        IRBuilder<>* nextInstructionBuilder,
        Instruction* instr,
        std::mutex& builderMutex,
        json *seglist,
        Module& M) = 0;
    virtual ~PatternMutator() {}
    private:
        bool isMutationDebugLoc(const Instruction *instr, const json &segref);
    protected:
        bool isMutationLocation(Instruction* instr, json *seglist, int type);
        bool isMutationLocation(Instruction* instr, json *seglist, const std::vector<int>* types);
};

// CallInst types of instruction mutators

/*
 * For the given function it replaces all locks and unlocks in the function.
 */
class PThreadPatternMutator: public PatternMutator{
    public:
        bool mutate (
                IRBuilder<>* builder,
                IRBuilder<>* nextInstructionBuilder,
                Instruction* instr,
                std::mutex& builderMutex,
                json *seglist,
                Module& M
        );
};

/*
 * On malloc it allocates one byte less memory.
 */
class MallocPatternMutator: public PatternMutator{
    public:
        bool mutate (
                IRBuilder<>* builder,
                IRBuilder<>* nextInstructionBuilder,
                Instruction* instr,
                std::mutex& builderMutex,
                json *seglist,
                Module& M
        );
};
/*
 * On fgets it allows to read more bytes than intended by the developer (concretely if X bytes should have been
 */
class FGetsPatternMutator: public PatternMutator{
    public:
        bool mutate (
                IRBuilder<>* builder,
                IRBuilder<>* nextInstructionBuilder,
                Instruction* instr,
                std::mutex& builderMutex,
                json *seglist,
                Module& M
        );
};

// ICmpInst types of instruction mutators

/*
 * The mutator for both ICMP_SGT, ICMP_SGE will be the same.
 * It changes one of the operators to cause an off-by one error.
 */
class GreaterThanPatternMutator: public PatternMutator{
    public:
        bool mutate (
                IRBuilder<>* builder,
                IRBuilder<>* nextInstructionBuilder,
                Instruction* instr,
                std::mutex& builderMutex,
                json *seglist,
                Module& M
        );
};
/*
 * The mutator for both ICMP_SLT, ICMP_SLE will be the same
 * It changes one of the operators to cause an off-by-one error.
 */
class LessThanPatternMutator: public PatternMutator{
    public:
        bool mutate (
                IRBuilder<>* builder,
                IRBuilder<>* nextInstructionBuilder,
                Instruction* instr,
                std::mutex& builderMutex,
                json *seglist,
                Module& M
        );
};

// misc types of instruction mutators

/*
 * On all function returns it frees all arguments that are pointers, for each argument a unique mutant is created.
 */
class FreeArgumentReturnPatternMutator: public PatternMutator{
    public:
        bool mutate (
                IRBuilder<>* builder,
                IRBuilder<>* nextInstructionBuilder,
                Instruction* instr,
                std::mutex& builderMutex,
                json *seglist,
                Module& M
        );
};

/*
 * For the given function it takes the return value of the compare exchange and replaces the compare result with true.
 */
class CMPXCHGPatternMutator: public PatternMutator{
    public:
        bool mutate (
                IRBuilder<>* builder,
                IRBuilder<>* nextInstructionBuilder,
                Instruction* instr,
                std::mutex& builderMutex,
                json *seglist,
                Module& M
        );
};

/*
 * If we have at least one atomicrmw instruction, we replace the atomicrmw with its non-atomic counterpart.
 */
class ATOMICRMWPatternMutator: public PatternMutator{
    public:
        bool mutate (
                IRBuilder<>* builder,
                IRBuilder<>* nextInstructionBuilder,
                Instruction* instr,
                std::mutex& builderMutex,
                json *seglist,
                Module& M
        );
    private:
        /*
        * TODO: some versions of atomic instructions are not yet implemented
        * Takes the given atomic instruction and replaces it with its non-atomic counterpart.
        */
        bool convertAtomicBinOpToBinOp(AtomicRMWInst* instr, IRBuilder<>* nextInstructionBuilder);
};

#endif //LLVM_MUTATION_TOOL_MUTATOR_LIB_H
