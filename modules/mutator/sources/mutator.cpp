#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <thread>

#include <llvm/Pass.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>


using namespace llvm;

#define DEBUG_TYPE "mutator"

cl::opt<std::string> InputFilename("mutation_patterns",
                                   cl::desc("file containing the mutation patterns"),
                                   cl::value_desc("filename"));

//counter which is used to assign for each basic block a unique ID
int bbIDCounter = 0;

//counter for method calls, each method call gets a unique ID
int callIDCounter = 1;

// a counter and the number of functions to print the current status
int number_functions = 0;
int funcounter = 0;

class Worker
{
private:

    std::mutex& builderMutex;
    llvm::Module& M;

public:

    explicit Worker() = delete;

    Worker(Module& M, std::mutex& builderMutex)
        : builderMutex(builderMutex)
        , M(M)
    {

    }

    void instrumentFunctions(std::vector<Function*> functions)
    {
        for (auto F: functions)
        {
            builderMutex.lock();
            std::cout << "[INFO] in thread " << std::this_thread::get_id() << ": "
                      << "instrumenting function " << ++funcounter << " of " << number_functions
                      << ": " << F->getName().data()
                      << std::endl;
            builderMutex.unlock();

//            instrumentFunction(*F);
        }
    }
};

struct MutatorPlugin : public ModulePass
{
    static char ID; // Pass identification, replacement for typeid
    MutatorPlugin() : ModulePass(ID) {}

    bool runOnModule(Module& M)
    {
        auto& llvm_context = M.getContext();

        // TODO read mutation patterns



        std::mutex builderMutex;
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

        number_functions = i;
        std::vector<std::thread> threads;
        for (auto& functions : threadFunctions)
        {
            threads.push_back(std::thread(&Worker::instrumentFunctions, new Worker(M, builderMutex), functions));
        }

        for (auto& thread : threads)
        {
            thread.join();
        }

        return true;
    }
};

char MutatorPlugin::ID = 0;
static RegisterPass<MutatorPlugin> X("mutatorplugin", "Plugin to mutate a bitcode file.");
