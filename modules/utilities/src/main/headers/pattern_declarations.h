//
// Created by Björn Mathis on 03.11.20.
//

#ifndef LLVM_MUTATION_TOOL_PATTERN_DECLARATIONS_H
#define LLVM_MUTATION_TOOL_PATTERN_DECLARATIONS_H

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
#include <cxxabi.h>
#include <set>
#include <iostream>
#include <../dependencies/json.hpp>

using json = nlohmann::json;

using namespace llvm;

// The most abstract base class
class Pattern
{
public:

    Pattern();
    explicit Pattern(json* pattern);
    // Pure Virtual Function
    virtual bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M) = 0;

    virtual std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) = 0;
    virtual ~Pattern() = default;
    static int PatternIDCounter;

private:
    static bool isMutationDebugLoc(const Instruction *instr, const json &segref);
protected:
    json seglist;
    static bool isMutationLocation(Instruction* instr, json *seglist, int type);
    static bool isMutationLocation(Instruction* instr, json *seglist, const std::vector<int>* types);

    static std::string getIdentifierString(const Instruction *instr, int id, IRBuilder<>* builder, std::mutex& builderMutex, Module& M, int type);
    /**
     * Does not add the mutation found signal at this position.
     * @param instr
     * @param builder
     * @param builderMutex
     * @param M
     * @param type
     * @return
     */
    static std::string getIdentifierString_unsignaled(const Instruction *instr, int id, int type);
    static std::string getIdentifierString(const Instruction *instr, int id, IRBuilder<>* builder, std::mutex& builderMutex, Module& M, int type, json& additionalInfo);
    /**
     * Does not add the mutation found signal at this position.
     * @param instr
     * @param builder
     * @param builderMutex
     * @param M
     * @param type
     * @param additionalInfo
     * @return
     */
    static std::string getIdentifierString_unsignaled(const Instruction *instr, int id, int type, const json &additionalInfo);

    static void addMutationFoundSignal(IRBuilder<>* builder, Module& M, int UID);

};

// Abstract base classes for CallInst types of instruction patterns
class CallInstPattern: virtual public Pattern {
public:
    using Pattern::Pattern;
protected:
    StringRef funNameString;
    void getfunNameString(const Instruction *instr);
    std::string demangle(const Instruction *instr);
};

// Abstract base classes for ICmpInst types of instruction patterns
class ICmpInstPattern: virtual public Pattern {
public:
    using Pattern::Pattern;
protected:
    llvm::CmpInst::Predicate predicate;
    // auto predicate = icmpinst->getPredicate();
    void getpredicate(const Instruction *instr);
    bool isMutateable(const CmpInst::Predicate pred, const Instruction* instr);
    static Value* insertMutationFunctionCall(Value* toMutate, IRBuilder<> *builder, Module &M, const std::string& function);
};

// Abstract base classes for Threading types of instruction patterns
class ThreadingPattern: virtual public Pattern {
public:
    using Pattern::Pattern;
protected:
    std::set<std::string> pthreadFoundFunctions;
};

// Abstract base class for failing calls to the libc.
// We change the call s.t. it always fails and flip all local checks that try to catch a failing call.
class LibCFailPattern: virtual public CallInstPattern {
public:
    using CallInstPattern::CallInstPattern;
protected:
    /**
     * For the given value find all compare instructions that use this value.
     */
    std::set<CmpInst*> foundCompareUses;

    /**
     * Returns a list of pattern found location if the function name matches.
     * This list can be directly returned from the find method.
     * @param instr: the current instruction to check
     * @param funName: the function name to find
     * @return
     */
    std::vector<std::string> findConcreteFunction(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module& M, const std::string& funName, int patternID);

    /**
     * Handles the concrete mutation for each libc function we want to fail
     * @param builder
     * @param nextInstructionBuilder
     * @param instr
     * @param builderMutex
     * @param seglist
     * @param M
     * @param patternID
     * @param returnValueForFail: The value returned from the mutated function if it fails.
     * @return
     */
    bool concreteMutate(
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M,
            int patternID,
            int returnValueForFail
    );
};

// CallInst types of instruction patterns
class MallocPattern: public CallInstPattern{
public:
    using CallInstPattern::CallInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class CallocPattern: public CallInstPattern{
public:
    using CallInstPattern::CallInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class FGetsPattern: public CallInstPattern{
public:
    using CallInstPattern::CallInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class PThreadPattern: public CallInstPattern, public ThreadingPattern{
public:
    using CallInstPattern::CallInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class NewArrayPattern: public CallInstPattern{
public:
    using CallInstPattern::CallInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

// ICmpInst types of instruction patterns
class SignedLessThanEqualToPattern: public ICmpInstPattern{
public:
    using ICmpInstPattern::ICmpInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

//class SignedLessThanEqualToSquaredPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};

class SignedLessThanPattern: public ICmpInstPattern{
public:
    using ICmpInstPattern::ICmpInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

//class SignedLessThanSquaredPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};

class UnsignedLessThanEqualToPattern: public ICmpInstPattern{
public:
    using ICmpInstPattern::ICmpInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

//class UnsignedLessThanEqualToSquaredPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};

class UnsignedLessThanPattern: public ICmpInstPattern{
public:
    using ICmpInstPattern::ICmpInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

//class UnsignedLessThanSquaredPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};

class SignedGreaterThanEqualToPattern: public ICmpInstPattern{
public:
    using ICmpInstPattern::ICmpInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

//class SignedGreaterThanEqualToHalvedPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};
//
//class SignedGreaterThanEqualToSqrtPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};

class SignedGreaterThanPattern: public ICmpInstPattern{
public:
    using ICmpInstPattern::ICmpInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

//class SignedGreaterThanSqrtPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};
//
//class SignedGreaterThanHalvedPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};

class UnsignedGreaterThanEqualToPattern: public ICmpInstPattern{
public:
    using ICmpInstPattern::ICmpInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

//class UnsignedGreaterThanEqualToSqrtPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};
//
//class UnsignedGreaterThanEqualToHalvedPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};

class UnsignedGreaterThanPattern: public ICmpInstPattern{
public:
    using ICmpInstPattern::ICmpInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

//class UnsignedGreaterThanSqrtPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};
//
//class UnsignedGreaterThanHalvedPattern: public ICmpInstPattern{
//public:
//    using ICmpInstPattern::ICmpInstPattern;
//    std::vector<std::string>
//    find(const Instruction *instr, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
//    bool mutate (
//            IRBuilder<>* builder,
//            IRBuilder<>* nextInstructionBuilder,
//            Instruction* instr,
//            std::mutex& builderMutex,
//            Module& M
//    ) override;
//};



class SignedToUnsigned: public ICmpInstPattern{
public:
    using ICmpInstPattern::ICmpInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};


class UnsignedToSigned: public ICmpInstPattern{
public:
    using ICmpInstPattern::ICmpInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

// Misc types of instruction patterns
class FreeArgumentReturnPattern: public Pattern{
public:
    using Pattern::Pattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class CMPXCHGPattern: public ThreadingPattern{
public:
    using ThreadingPattern::ThreadingPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
private:
    std::set<std::string> cmpxchgFoundFunctions;
};

class ATOMICRMWPattern: public ThreadingPattern{
public:
    using ThreadingPattern::ThreadingPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
private:
    /*
    * TODO: some versions of atomic instructions are not yet implemented
    * Takes the given atomic instruction and replaces it with its non-atomic counterpart.
    */
    static bool convertAtomicBinOpToBinOp(AtomicRMWInst* instr, json *seglist, IRBuilder<>* nextInstructionBuilder, Module& M);
    bool foundAtomicRMW = false;
};


class ShiftSwitch: public Pattern{
public:
    using Pattern::Pattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class SwitchPlusMinus: public Pattern{
public:
    using Pattern::Pattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};


class RedirectBranch: public Pattern{
public:
    using Pattern::Pattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class UnInitLocalVariables: public Pattern{
public:
    using Pattern::Pattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;

private:
    std::set<StoreInst*> to_delete;
};

/*
 * The mutator for ICMP_EQ.
 * A preceding "load" instruction needs to be changed into a "store" instruction.
 * Which is why this isn't a ICmpPattern subclass.
 * It changes the "==" sign to "=" in a comparision.
 * The users of each load operation is searched and if an "icmp eq" instruction
 * is one of the users, then the load and the icmp instructions are mutated accordingly.
 */
class CompareEqualToPattern: public Pattern{
public:
    using Pattern::Pattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class DeleteArgumentReturnPattern: public Pattern{
public:
    using Pattern::Pattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class DeleteStorePattern: public Pattern{
public:
    using Pattern::Pattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
            ) override;
};

class DeleteCallInstructionPattern: public CallInstPattern{
public:
    using CallInstPattern::CallInstPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
            ) override;
};

class INetAddrFailPattern: public LibCFailPattern{
public:
    using LibCFailPattern::LibCFailPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};


class PrintfPattern: public LibCFailPattern{
public:
    using LibCFailPattern::LibCFailPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class SPrintfPattern: public LibCFailPattern{
public:
    using LibCFailPattern::LibCFailPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class SNPrintfPattern: public LibCFailPattern{
public:
    using LibCFailPattern::LibCFailPattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
    ) override;
};

class ReassignStoreInstructionPattern: public Pattern{
public:
    using Pattern::Pattern;
    std::vector<std::string>
    find(const Instruction *instr, int id, IRBuilder<> *builder, std::mutex &builderMutex, Module &M) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            Module& M
            ) override;
private:
    // returns a previous store instruction with the same types if it exists in the current basic block
    const Instruction* getPrevStore(const Instruction *current, Type* origType);
};
#endif //LLVM_MUTATION_TOOL_PATTERN_DECLARATIONS_H
