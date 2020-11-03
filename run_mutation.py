#!/usr/bin/env python3
"""
A python script for orchestrating the mutation of subjects.
"""
import sys
import subprocess
import argparse

def main(prog: str):
    """
    Takes the program as argument, checks if it is in a compilable form, converts it to an .ll file if necessary and
    then performs the actual mutation.
    :param prog:
    :return:
    """
    if prog.endswith(".bc"):
        subprocess.run(["clang", "-S", "-emit-llvm", prog, "-o", f"{prog[:-3]}.ll"])
        mutate = f"{prog[:-3]}.ll"
    else:
        mutate = prog
    subprocess.run(["python3", "build/install/LLVM_Mutation_Tool/bin/compileAndFind.py", mutate])

    arguments = ["python3", "build/install/LLVM_Mutation_Tool/bin/Mutate.py", "-p", mutate]
    if args.bitcode:
        arguments.append("-bc")
    if args.bitcode_human_readable:
        arguments.append("-ll")
    if args.binary:
        arguments.append("-bn")
    subprocess.run(arguments)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mutator Script")
    parser.add_argument('-bc', "--bitcode", action='store_true', help="Keeps the mutated bitcode files.")
    parser.add_argument('-ll', "--bitcode_human_readable", action='store_true', help="Keeps the mutated bitcode files as human readable files.")
    parser.add_argument('-bn', "--binary", action='store_true', help="Creates mutated runnable binaries.")
    parser.add_argument('-p', "--program", default="", type=str, required=True,
                        help="Path to the source file that will be mutated. Use at least one of the arguments [-bc, -ll, -bn] to get "
                             "resulting files.")
    args = parser.parse_args(sys.argv[1:])

    main(args.program)