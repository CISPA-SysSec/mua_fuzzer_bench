import subprocess
import sys
import os
import argparse
import shlex

llvm_bindir = "@LLVM_BINDIR@"
opt = f"{llvm_bindir}/opt"
mutatorplugin = "@MUTATOR_PLUGIN@"
is_cpp = False

dynamic_libraries_folder = "@DYN_LIB_FOLDER@"
linked_libraries = "dynamiclibrary"

SYSROOT = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/"

def run(args, **kwargs):
    print(args, kwargs, flush=True)
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    print(proc.stdout.decode(), flush=True)
    return proc

def compile_and_find(args):
    # "${CLANG}" -g -S -D_FORTIFY_SOURCE=0 "${SYSROOT}" -emit-llvm -include "${INCDIR}/traceinstr/wrapper_libc.h" -o "${PROG_SOURCE}.uninstrumented.bc" -x c "${PROG_SOURCE}"
    print("compile and find args:", args)

    if args.cpp:
        clang = f"{llvm_bindir}/clang++"
    else:
        clang = f"{llvm_bindir}/clang"

    progsource = args.program
    # used for both compilation of the .ll file and the detection bin
    bc_args = shlex.split(args.bc_args)
    # used only for the compilation of the detection bin
    bin_args = shlex.split(args.bin_args)

    # First compile a intermediate .ll file that is analyzed for possible mutations.
    uname = os.uname()
    # Macos catalina and newer need sysroot to be defined when compiling
    # According to https://en.wikipedia.org/wiki/Darwin_%28operating_system%29#Release_history,
    # Catalina corresponds to Darwin's major version number 19.
    # The uname.release check below checks if the major version number of Darwin is greater than 18
    if uname.sysname== "Darwin" and int(uname.release.split('.')[0]) >= 19:
        # if (uname["release"]):
        run([clang, "-g", "-S", "-D_FORTIFY_SOURCE=0", "-isysroot",
                         f"{SYSROOT}", "-emit-llvm",
                         *bc_args, progsource,
                         "-o", f"{progsource}.ll"])
    else:
        run([clang, "-g", "-S", "-D_FORTIFY_SOURCE=0", "-emit-llvm",
                        *bc_args, progsource,
                        "-o", f"{progsource}.ll"])

    # "${LLVM}/opt" -S -instnamer -reg2mem -load "${TRACEPLUGIN}" -traceplugin -exclude_functions "${EXCLUDED_FUNCTIONS}" -disable-verify "${PROG_SOURCE}.uninstrumented.bc" -o  "${PROG_SOURCE}.opt_debug.bc"

    # Do the analysis for possible mutations.
    with open(f"{progsource}.ll", "r") as progsource_file:
        sp_call_args = [opt, "-S", "-load", mutatorplugin, "-mutationfinder",
            "-mutation_patterns", f"{progsource}.mutationlocations",  "-disable-verify",
            "-o", f"{progsource}.opt_mutate.ll"]
        if is_cpp:
            sp_call_args.append("-cpp")

        subprocess.call(sp_call_args, stdin=progsource_file)

    # compile to a binary to find out what mutations could possibly be triggered
    print("Now Compile!")
    arguments = [
        # "-v",
        f"{progsource}.opt_mutate.ll", # input file
        *bc_args,
        *bin_args,
        f"-L{dynamic_libraries_folder}", # points the runtime linker to the location of the included shared library
        "-lm", "-lz", "-ldl", # some often used libraries
        f"-l{linked_libraries}", # the library containing all the api functions that were called by mutations
        "-o", f"{progsource}.opt_mutate", # output file
    ]
    if uname.sysname == "Darwin" and int(uname.release.split('.')[0]) >= 19:
        run([clang, "-fno-inline", "-O3", "-isysroot", f"{SYSROOT}"] + arguments)
    else:
        run([clang, "-fno-inline", "-O3"] + arguments)


def main():
    parser = argparse.ArgumentParser(description="Script to find patterns.")
    compiler = parser.add_mutually_exclusive_group(required=True)
    compiler.add_argument('-cc', "--cc", action='store_true', help="Uses clang for compilation.")
    compiler.add_argument('-cpp', "--cpp", action='store_true', help="Uses clang++ for compilation.")

    parser.add_argument("--bc-args", default="",
                        help="Compiler arguments that should be used for compilation for all artifacts.")
    parser.add_argument("--bin-args", default="",
                        help="Compiler arguments that should be used for compilation of the binary.")
    parser.add_argument("program", type=str,
                        help="Path to the source file in which patterns will be searched.")

    args = parser.parse_args(sys.argv[1:])

    if args.cpp:
        clang = f"{llvm_bindir}/clang++"
        global is_cpp
        is_cpp = True
    compile_and_find(args)


if __name__ == "__main__":
    main()

