//
// Created by Björn Mathis on 11.09.20.
//
#ifndef LLVM_MUTATION_TOOL_PATTERN_LIB_H
#define LLVM_MUTATION_TOOL_PATTERN_LIB_H


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


using namespace llvm;

std::vector<std::string> look_for_pattern(Instruction* instr);
void populatePatternVectors();
// The most abstract base class
class Pattern
{
    public:
        // Pure Virtual Function
        virtual std::vector<std::string> find(const Instruction *instr) = 0;
        virtual ~Pattern() {}
    protected:
        static std::string getIdentifierString(const Instruction *instr, int type, const std::string& additionalInfo="");
};

// Abstract base classes for CallInst types of instruction patterns
class CallInstPattern: public Pattern {
    public:
        // Pure Virtual Function
        virtual std::vector<std::string> find(const Instruction *instr) = 0;
    protected:
        StringRef funNameString;
        void getfunNameString(const Instruction *instr);
};

// Abstract base classes for ICmpInst types of instruction patterns
class ICmpInstPattern: public Pattern {
    public:
        // Pure Virtual Function
        virtual std::vector<std::string> find(const Instruction *instr) = 0;
    protected:
        llvm::CmpInst::Predicate predicate;
        // auto predicate = icmpinst->getPredicate();
        void getpredicate(const Instruction *instr);
};

// Abstract base classes for Threading types of instruction patterns
class ThreadingPattern: public Pattern {
public:
    // Pure Virtual Function
    virtual std::vector<std::string> find(const Instruction *instr) = 0;
protected:
    std::set<std::string> pthreadFoundFunctions;
};

// CallInst types of instruction patterns
class MallocPattern: public CallInstPattern{
    public:
        std::vector<std::string> find(const Instruction *instr);
};

class FGetsPattern: public CallInstPattern{
    public:
        std::vector<std::string> find(const Instruction *instr);
};

class PThreadPattern: public CallInstPattern, public ThreadingPattern{
    public:
        std::vector<std::string> find(const Instruction *instr);
};


// ICmpInst types of instruction patterns
class LessThanEqualToPattern: public ICmpInstPattern{
    public:
        std::vector<std::string> find(const Instruction *instr);
};

class GreaterThanPattern: public ICmpInstPattern{
    public:
        std::vector<std::string> find(const Instruction *instr);
};

// Misc types of instruction patterns
class FreeArgumentReturnPattern: public Pattern{
    public:
        std::vector<std::string> find(const Instruction *instr);
};

class CMPXCHGPattern: public ThreadingPattern{
    public:
        std::vector<std::string> find(const Instruction *instr);
    private:
        std::set<std::string> cmpxchgFoundFunctions;
};

class ATOMICRMWPattern: public ThreadingPattern{
    public:
        std::vector<std::string> find(const Instruction *instr);
    private:
        bool foundAtomicRMW = false;
};

#endif //LLVM_MUTATION_TOOL_PATTERN_LIB_H
