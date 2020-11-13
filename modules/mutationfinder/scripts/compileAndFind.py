import subprocess
import sys
import os
import argparse

llvm_bindir = "@LLVM_BINDIR@"
clang = f"{llvm_bindir}/clang"
opt = f"{llvm_bindir}/opt"
mutatorplugin = "@MUTATOR_PLUGIN@"

sysroot = ""
progsource = None

def main():
    # "${CLANG}" -g -S -D_FORTIFY_SOURCE=0 "${SYSROOT}" -emit-llvm -include "${INCDIR}/traceinstr/wrapper_libc.h" -o "${PROG_SOURCE}.uninstrumented.bc" -x c "${PROG_SOURCE}"
    uname = os.uname()
    # Macos catalina and newer need sysroot to be defined when compiling
    # TODO also check for actual version, not only if macos or not
    if uname.sysname== "Darwin":
        # if (uname["release"]):
        subprocess.call([clang, "-g", "-S", "-D_FORTIFY_SOURCE=0", "-isysroot", f"{sysroot}", "-emit-llvm", "-o", f"{progsource}.ll", progsource])
    else:
        subprocess.call([clang, "-g", "-S", "-D_FORTIFY_SOURCE=0", "-emit-llvm", "-o", f"{progsource}.ll", progsource])

    # "${LLVM}/opt" -S -instnamer -reg2mem -load "${TRACEPLUGIN}" -traceplugin -exclude_functions "${EXCLUDED_FUNCTIONS}" -disable-verify "${PROG_SOURCE}.uninstrumented.bc" -o  "${PROG_SOURCE}.opt_debug.bc"

    with open(f"{progsource}.ll", "r") as progsource_file:
        subprocess.call([opt, "-S", "-load", mutatorplugin, "-mutationfinder", "-mutation_patterns", f"{progsource}.mutationlocations",  "-disable-verify", "-o", f"{progsource}.opt_mutate.ll"], stdin=progsource_file)



if __name__=="__main__":
    parser = argparse.ArgumentParser(description="Mutator Script")
    parser.add_argument('-bc', "--bitcode", action='store_true', help="Keeps the mutated bitcode files.")
    parser.add_argument('-ll', "--bitcode_human_readable", action='store_true', help="Keeps the mutated bitcode files as human readable files.")
    parser.add_argument('-bn', "--binary", action='store_true', help="Creates mutated runnable binaries.")
    parser.add_argument('-cpp', "--cpp", action='store_true', help="Uses clang++ instead of clang for compilation.")
    parser.add_argument('-p', "--program", default="", type=str, required=True,
                        help="Path to the source file that will be mutated. Use at least one of the arguments [-bc, -ll, -bn] to get "
                             "resulting files.")
    args = parser.parse_args(sys.argv[1:])

    if args.cpp:
        clang = f"{llvm_bindir}/clang++"

    if args.program:
        progsource = args.program
        sysroot = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/"
        main()
    else:
        pass
        # TODO raise error