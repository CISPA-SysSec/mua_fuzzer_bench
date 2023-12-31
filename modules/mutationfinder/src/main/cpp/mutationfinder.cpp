#include <iostream>
#include <fstream>
#include <map>
#include <thread>

#include "pattern_lib.h"

#include <llvm/Pass.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "mutationfinder"

cl::opt<std::string> MutationLocationFile("mutation_patterns",
                                   cl::desc("file containing the mutation patterns"),
                                   cl::value_desc("filename"));
cl::opt<bool> CPP ("cpp", cl::desc("Enable CPP-only mutations"));
namespace {
// a counter and the number of functions to print the current status
int number_functions = 0;
int funcounter = 0;

std::ofstream mutationLocationsstream;
std::vector<std::string> mutationLocationsvector;
json callgraph;

class Worker
{
private:

    std::mutex& builderMutex;
    std::mutex& vectorMutex;
    llvm::Module& M;

public:

    explicit Worker() = delete;

    Worker(Module& M, std::mutex& builderMutex, std::mutex& vectorMutex)
        : builderMutex(builderMutex)
        , vectorMutex(vectorMutex)
        , M(M)
    {

    }

    /**
     * Instrument all functions given as parameter.
     * @param functions
     */
    void findPatternInFunctions(std::vector<Function*> functions)
    {
        for (auto F: functions)
        {
            builderMutex.lock();
            std::cout << "[INFO] in thread " << std::this_thread::get_id() << ": "
                      << "instrumenting function " << ++funcounter << " of " << number_functions
                      << ": " << F->getName().data()
                      << std::endl;
            builderMutex.unlock();
            findPatternInFunction(*F);
        }
    }




    /**
     * Instrument the given instruction with the given builders.
     * @param instr
     * @param builder
     * @param nextInstructionBuilder
     */
    void handInstructionToPatternMatchers(Instruction* instr, int id)
    {
        // Handle call instructions with function call pattern analyzer
        if (auto* callinst = dyn_cast<CallInst>(instr))
        {
            Function* fun = callinst->getCalledFunction();
            if (fun != nullptr && fun->isIntrinsic() && !dyn_cast<MemCpyInst>(callinst) && !dyn_cast<MemMoveInst>(callinst)
                && !dyn_cast<VAStartInst>(callinst) && !dyn_cast<VAArgInst>(callinst) && !dyn_cast<VACopyInst>(callinst)
                && !dyn_cast<VAEndInst>(callinst))
            {
                // skip llvm intrinsic functions other than llvm.memcpy and llvm memmove
                return;
            }

        }
        builderMutex.lock();
        BasicBlock::iterator itr_bb(instr);
        IRBuilder<> builder(instr->getParent(), itr_bb);
        IRBuilder<> nextInstructionBuilder(instr->getParent(), std::next(itr_bb, 1));
        auto patternLocations = look_for_pattern(&builder, &nextInstructionBuilder, instr, id, builderMutex, M);
        builderMutex.unlock();
        for (const auto& loc: patternLocations) {
            if (!loc.empty()) {
                // N.B Assuming not a very lot of mutation locations in a file
                // Otherwise mutationLocationsvector may eat up a lot of RAM.
                vectorMutex.lock();
                mutationLocationsvector.push_back(loc);
                vectorMutex.unlock();
            }
        }
    }


    /**
     * Instrument one function, i.e. run over all instructions in that function and instrument them.
     * @param F the given function
     * @return true on successful instrumentation
     */
    bool findPatternInFunction(Function& F)
    {
        std::vector<Instruction*> toInstrument;
        std::vector<int> fID;
        int counter = 0;
        for (BasicBlock& bb : F)
        {
            auto first_insertion_point = bb.getFirstInsertionPt();

            for (BasicBlock::iterator itr_bb = first_insertion_point; itr_bb != bb.end(); ++itr_bb)
            {
                toInstrument.push_back(&*itr_bb);
                fID.push_back(counter++);
            }
        }

        auto funNameArray = json::array();
        counter = 0;
        for (Instruction* instr : toInstrument)
        {
            auto* callinst = dyn_cast<CallBase>(instr);
            if (callinst)
            {
                Function* fun = callinst->getCalledFunction();
                std::string result;
                if (fun != nullptr) {
                    if (!fun->isIntrinsic()) {
                       result += fun->getName().str() + " | ";
                       std::string type_str;
                       llvm::raw_string_ostream rso(type_str);
                       callinst->getType()->print(rso);
                       result += rso.str() + " | ";
                       for (int i = 0; i < callinst->getNumArgOperands(); i++) {
                           std::string type_str_inner;
                           llvm::raw_string_ostream rso_inner(type_str_inner);
                           callinst->getArgOperand(i)->getType()->print(rso_inner);
                           result +=  rso_inner.str() + " | ";
                       }
                       funNameArray.push_back(result);
                    }
                } else {
                    std::string type_str;
                    llvm::raw_string_ostream rso(type_str);
                    callinst->getType()->print(rso);
                    result += ":unnamed: | " + rso.str() + " | ";
                    for (int i = 0; i < callinst->getNumArgOperands(); i++) {
                        std::string type_str_inner;
                        llvm::raw_string_ostream rso_inner(type_str_inner);
                        callinst->getArgOperand(i)->getType()->print(rso_inner);
                        result += rso_inner.str() + " | ";
                    }
                    funNameArray.push_back(result);
                }
            }
            handInstructionToPatternMatchers(instr, fID[counter++]);
        }

        builderMutex.lock();
        std::string result_string = F.getName().str() + " | ";
        std::string type_str;
        llvm::raw_string_ostream rso(type_str);
        F.getFunctionType()->getReturnType()->print(rso);
        result_string += rso.str() + " | ";
        for (int i = 0; i < F.getFunctionType()->getNumParams(); i++) {
            std::string type_str_inner;
            llvm::raw_string_ostream rso_inner(type_str_inner);
            F.getFunctionType()->getParamType(i)->print(rso_inner);
            result_string += rso_inner.str() + " | ";
        }
        std::cout << result_string << "\n";
        callgraph[result_string] = funNameArray;
        builderMutex.unlock();
        return true;
    }
};

struct MutatorPlugin : public ModulePass
{
    static char ID; // Pass identification, replacement for typeid
    MutatorPlugin() : ModulePass(ID) {}

    bool runOnModule(Module& M) override
    {
        auto& llvm_context = M.getContext();

        // TODO read mutation patterns



        std::mutex builderMutex;
        std::mutex vectorMutex;
        mutationLocationsstream.open(MutationLocationFile);
        mutationLocationsstream << "[";
        unsigned int concurrentThreadsSupported = ceil(std::thread::hardware_concurrency() * 30);
        std::cout << "[INFO] number of threads: " << concurrentThreadsSupported << std::endl;

        std::vector<std::vector<Function*>> threadFunctions(concurrentThreadsSupported);
        auto i = 0;
        for (Function& f : M.functions())
        {
            if (f.isDeclaration())
            {
                continue;
            }

            threadFunctions[i % concurrentThreadsSupported].push_back(&f);
            ++i;
        }
        populatePatternVectors(CPP);
        insertMutationApiFunctions(M, CPP);
        number_functions = i;
        std::vector<std::thread> threads;
        for (auto& functions : threadFunctions)
        {
            threads.push_back(std::thread(&Worker::findPatternInFunctions, new Worker(M, builderMutex, vectorMutex), functions));
        }

        for (auto& thread : threads)
        {
            thread.join();
        }
        for (int vecSizeCounter = 0; vecSizeCounter < mutationLocationsvector.size(); vecSizeCounter++)
        {
            if (vecSizeCounter != 0) mutationLocationsstream << ",\n";
            mutationLocationsstream << mutationLocationsvector[vecSizeCounter];
        }
        mutationLocationsstream << "]";
        mutationLocationsstream.close();
        std::ofstream graphStream;
        graphStream.open(std::string(MutationLocationFile.c_str()) + ".graph");
        graphStream << callgraph.dump(4);
        graphStream.close();
        return true;
    }
};
}

char MutatorPlugin::ID = 0;
static RegisterPass<MutatorPlugin> X("mutationfinder", "Plugin to mutate a bitcode file.");

static RegisterStandardPasses Y(
        PassManagerBuilder::EP_OptimizerLast,
        [](const PassManagerBuilder &Builder,
           legacy::PassManagerBase &PM) { PM.add(new MutatorPlugin()); });

