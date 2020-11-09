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
#include <set>
#include <../dependencies/json.hpp>

using json = nlohmann::json;

using namespace llvm;

// The most abstract base class
class Pattern
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

    virtual std::vector<std::string> find(const Instruction *instr) = 0;
    virtual ~Pattern() = default;

private:

    static bool isMutationDebugLoc(const Instruction *instr, const json &segref);
protected:
    static bool isMutationLocation(Instruction* instr, json *seglist, int type);
    static bool isMutationLocation(Instruction* instr, json *seglist, const std::vector<int>* types);

    static std::string getIdentifierString(const Instruction *instr, int type);
    static std::string getIdentifierString(const Instruction *instr, int type, json& additionalInfo);
};

// Abstract base classes for CallInst types of instruction patterns
class CallInstPattern: public Pattern {
protected:
    StringRef funNameString;
    void getfunNameString(const Instruction *instr);
};

// Abstract base classes for ICmpInst types of instruction patterns
class ICmpInstPattern: public Pattern {
protected:
    llvm::CmpInst::Predicate predicate;
    // auto predicate = icmpinst->getPredicate();
    void getpredicate(const Instruction *instr);
};

// Abstract base classes for Threading types of instruction patterns
class ThreadingPattern: public Pattern {
protected:
    std::set<std::string> pthreadFoundFunctions;
};

// CallInst types of instruction patterns
class MallocPattern: public CallInstPattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
};

class CallocPattern: public CallInstPattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
};

class FGetsPattern: public CallInstPattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
};

class PThreadPattern: public CallInstPattern, public ThreadingPattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
};


// ICmpInst types of instruction patterns
class LessThanEqualToPattern: public ICmpInstPattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
};

class GreaterThanPattern: public ICmpInstPattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
};

class SignedToUnsigned: public ICmpInstPattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
};


class UnsignedToSigned: public ICmpInstPattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
};

// Misc types of instruction patterns
class FreeArgumentReturnPattern: public Pattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
};

class CMPXCHGPattern: public ThreadingPattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
private:
    std::set<std::string> cmpxchgFoundFunctions;
};

class ATOMICRMWPattern: public ThreadingPattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
private:
    /*
    * TODO: some versions of atomic instructions are not yet implemented
    * Takes the given atomic instruction and replaces it with its non-atomic counterpart.
    */
    static bool convertAtomicBinOpToBinOp(AtomicRMWInst* instr, IRBuilder<>* nextInstructionBuilder);
    bool foundAtomicRMW = false;
};


class ShiftSwitch: public Pattern{
public:
    std::vector<std::string> find(const Instruction *instr) override;
    bool mutate (
            IRBuilder<>* builder,
            IRBuilder<>* nextInstructionBuilder,
            Instruction* instr,
            std::mutex& builderMutex,
            json *seglist,
            Module& M
    ) override;
};

#endif //LLVM_MUTATION_TOOL_PATTERN_DECLARATIONS_H
