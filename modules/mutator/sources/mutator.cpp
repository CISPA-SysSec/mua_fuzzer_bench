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

    /**
     * Instrument all functions given as parameter.
     * @param functions
     */
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

            mutateFunction(*F);
        }
    }

    /**
     * Mutate the given function call if a mutation pattern exists for the function.
     * @param builder the builder to add instruction in front of the call
     * @param nextInstructionBuilder the builder to add instructions after the call
     * @param instr the instruction to mutate (i.e. the function call)
     * @param funNameString the name of the function that is called
     * @return
     */
    bool mutateFunctionCall(IRBuilder<>* builder, IRBuilder<>* nextInstructionBuilder, Instruction* instr, const std::string& funNameString)
    {
        if (funNameString.find("malloc") != std::string::npos) {
            // substract 1 and give the new value to malloc
            Value* lhs;
            if (CallInst* callinst = dyn_cast<CallInst>(instr))
            {
                lhs = callinst->getArgOperand(0); // TODO a pattern could describe which argument to mutate
                builderMutex.lock();
                auto newVal = builder->CreateAdd(lhs, builder->getInt64(-1));
                builderMutex.unlock();
                callinst->setOperand(0, newVal);
            }
            std::cout << "Found malloc!\n";
            return true;
        }
        return false;
    }


    /**
     * Instrument the given instruction with the given builders.
     * @param instr
     * @param builder
     * @param nextInstructionBuilder
     */
    void mutateInstr(Instruction* instr, IRBuilder<>* builder, IRBuilder<>* nextInstructionBuilder)
    {
        // Call instructions are handled differently
        if (CallInst* callinst = dyn_cast<CallInst>(instr))
        {
            Function* fun = callinst->getCalledFunction();
            if (fun != nullptr && fun->isIntrinsic() && !dyn_cast<MemCpyInst>(callinst) && !dyn_cast<MemMoveInst>(callinst)
                && !dyn_cast<VAStartInst>(callinst) && !dyn_cast<VAArgInst>(callinst) && !dyn_cast<VACopyInst>(callinst)
                && !dyn_cast<VAEndInst>(callinst))
            {
                // skip llvm intrinsic functions other than llvm.memcpy and llvm memmove
                return;
            }

            std::string calledFunctionName;
            if (fun != nullptr)
            {
                calledFunctionName = fun->getName().str();
            }
            else
            {
                // called function might be unknown when using casts or indirect calls (through pointer)

                // try harder to find the function name by removing casts and aliases
                calledFunctionName = callinst->getCalledValue()->stripPointerCasts()->getName().str();
                if (calledFunctionName.empty())
                {
                    // as a last resort use 'null' for the name
                    // TODO (michael.mera) Really? It seems to me that 'null' is a misleading name, rather use 'unknown' or something similar.
                    calledFunctionName = "null";
                }
            }

            if (mutateFunctionCall(builder, nextInstructionBuilder, instr, calledFunctionName))
            {
                return;
            }
        }
    }


    /**
     * Instrument one function, i.e. run over all isntructions in that function and instrument them.
     * @param F the given function
     * @return true on successful instrumentation
     */
    bool mutateFunction(Function& F)
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
            mutateInstr(instr, &builder, &nextInstructionBuilder);
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
