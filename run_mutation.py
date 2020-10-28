#!/usr/bin/env python3
"""
A python script for orchestrating the mutation of subjects.
"""
import sys
import subprocess

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
    subprocess.run(["python3", "build/install/LLVM_Mutation_Tool/bin/Mutate.py", mutate])



if __name__ == "__main__":
    assert len(sys.argv) > 1, "no program given for mutation"
    main(sys.argv[1])