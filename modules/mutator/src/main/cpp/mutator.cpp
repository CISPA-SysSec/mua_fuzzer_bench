#include <fstream>
#include <map>
#include <thread>

#include "mutator_lib.h"

#include <llvm/Pass.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>



using namespace llvm;

#define DEBUG_TYPE "mutationfinder"

cl::opt<std::string> Mutation("mutation_pattern",
                                   cl::desc("the source location and mutation pattern"),
                                   cl::value_desc("string"));

//counter for method calls, each method call gets a unique ID
int callIDCounter = 1;

// a counter and the number of functions to print the current status
int number_functions = 0;
int funcounter = 0;

// the following variables define the location of the mutation as well as the pattern
// containing in order: Directory, File, line, column, mutation-ID as strings
json seglist;

std::ofstream mutationLocations;

class Worker
{
private:

    std::mutex& builderMutex;
    std::mutex& fileMutex;
    llvm::Module& M;

public:

    explicit Worker() = delete;

    Worker(Module& M, std::mutex& builderMutex, std::mutex& fileMutex)
        : builderMutex(builderMutex)
        , fileMutex(fileMutex)
        , M(M)
    {

    }

    /**
     * Instrument all functions given as parameter.
     * @param functions
     */
    void instrumentFunctions(std::vector<Function*> functions)
    {
        for (auto F: functions)
        {
//            builderMutex.lock();
//            std::cout << "[INFO] in thread " << std::this_thread::get_id() << ": "
//                      << "instrumenting function " << ++funcounter << " of " << number_functions
//                      << ": " << F->getName().data()
//                      << std::endl;
//            builderMutex.unlock();

            findPatternInFunction(*F);
        }
    }


    /**
     * Instrument the given instruction with the given builders.
     * @param instr
     * @param builder
     * @param nextInstructionBuilder
     */
    void handInstructionToPatternMatchers(Instruction* instr, IRBuilder<>* builder, IRBuilder<>* nextInstructionBuilder)
    {
        // Call instructions are handled differently
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
        mutatePattern(builder, nextInstructionBuilder, instr, builderMutex, &seglist, M);
    }


    /**
     * Instrument one function, i.e. run over all isntructions in that function and instrument them.
     * @param F the given function
     * @return true on successful instrumentation
     */
    bool findPatternInFunction(Function& F)
    {
        std::vector<Instruction*> toInstrument;
        for (BasicBlock& bb : F)
        {
            auto first_insertion_point = bb.getFirstInsertionPt();
//
//            IRBuilder<> builder(&bb, first_insertion_point);
//
//            std::vector<Value*> iHeaderArgs;
//            createStaticArgList(&builder, iHeaderArgs, &*first_insertion_point);
//            builderMutex.lock();
//            iHeaderArgs[0] = builder.getInt64(additionalOperators.at("bbenter")->opcode);
//            builder.CreateCall(tracer("instructionHeader"), iHeaderArgs);
//            std::vector<Value*> bbEnterArgs;
//            bbEnterArgs.push_back(builder.getInt64(bbIDCounter++));
//            builder.CreateCall(tracer("enterBasicBlock"), bbEnterArgs);
//            builder.CreateCall(tracer("instructionEnd"), {});
//            builderMutex.unlock();

            for (BasicBlock::iterator itr_bb = first_insertion_point; itr_bb != bb.end(); ++itr_bb)
            {
                toInstrument.push_back(&*itr_bb);
            }
        }

        for (Instruction* instr : toInstrument)
        {
            BasicBlock::iterator itr_bb(instr);
            builderMutex.lock();
            IRBuilder<> builder(instr->getParent(), itr_bb);
            IRBuilder<> nextInstructionBuilder(instr->getParent(), std::next(itr_bb, 1));
            builderMutex.unlock();
            handInstructionToPatternMatchers(instr, &builder, &nextInstructionBuilder);
        }

        return true;
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
        std::mutex fileMutex;
        // std::cout << "[INFO C] Mutating: " << Mutation << "\n";
        populateMutatorVectors();
        //Parsing the string into a json
        std::string segment;
        seglist = json::parse(Mutation);
        unsigned int concurrentThreadsSupported = ceil(std::thread::hardware_concurrency());
//        std::cout << "[INFO] number of threads: " << concurrentThreadsSupported << std::endl;

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
            threads.push_back(std::thread(&Worker::instrumentFunctions, new Worker(M, builderMutex, fileMutex), functions));
        }

        for (auto& thread : threads)
        {
            thread.join();
        }
        // TODO: Where is this opened and where it is used? - abhilashgupta
        mutationLocations.close();
        return true;
    }
};

char MutatorPlugin::ID = 0;
static RegisterPass<MutatorPlugin> X("mutatorplugin", "Plugin to mutate a bitcode file.");
