import subprocess
import sys
import os
import argparse

llvm_bindir = "@LLVM_BINDIR@"
clang = f"{llvm_bindir}/clang"
opt = f"{llvm_bindir}/opt"
mutatorplugin = "@MUTATOR_PLUGIN@"

dynamic_libraries_folder = "@DYN_LIB_FOLDER@"
linked_libraries = "dynamiclibrary"

sysroot = ""
progsource = None

def main():
    # "${CLANG}" -g -S -D_FORTIFY_SOURCE=0 "${SYSROOT}" -emit-llvm -include "${INCDIR}/traceinstr/wrapper_libc.h" -o "${PROG_SOURCE}.uninstrumented.bc" -x c "${PROG_SOURCE}"
    uname = os.uname()
    # Macos catalina and newer need sysroot to be defined when compiling
    # According to https://en.wikipedia.org/wiki/Darwin_%28operating_system%29#Release_history,
    # Catalina corresponds to Darwin's major version number 19.
    # The uname.release check below checks if the major version number of Darwin is greater than 18
    if uname.sysname== "Darwin" and int(uname.release.split('.')[0]) >= 19:
        # if (uname["release"]):
        subprocess.call([clang, "-g", "-S", "-D_FORTIFY_SOURCE=0", "-isysroot",
            f"{sysroot}", "-emit-llvm", "-o", f"{progsource}.ll", progsource])
    else:
        subprocess.call([clang, "-g", "-S", "-D_FORTIFY_SOURCE=0", "-emit-llvm",
                            "-o", f"{progsource}.ll", progsource])

    # "${LLVM}/opt" -S -instnamer -reg2mem -load "${TRACEPLUGIN}" -traceplugin -exclude_functions "${EXCLUDED_FUNCTIONS}" -disable-verify "${PROG_SOURCE}.uninstrumented.bc" -o  "${PROG_SOURCE}.opt_debug.bc"

    with open(f"{progsource}.ll", "r") as progsource_file:
        subprocess.call([opt, "-S", "-load", mutatorplugin, "-mutationfinder",
            "-mutation_patterns", f"{progsource}.mutationlocations",  "-disable-verify",
            "-o", f"{progsource}.opt_mutate.ll"], stdin=progsource_file)

    # compile to a binary to find out what mutations could possibly be triggered
    print("Now Compile!")
    arguments = [
        # "-v",
        "-o",
        f"{progsource}.opt_mutate", # output file
        f"{progsource}.opt_mutate.ll", # input file
        f"-L{dynamic_libraries_folder}", # points the runtime linker to the location of the included shared library
        "-lm", "-lz", "-ldl", # some often used libraries
        f"-l{linked_libraries}", # the library containing all the api functions that were called by mutations
    ]
    if uname.sysname == "Darwin" and int(uname.release.split('.')[0]) >= 19:
        subprocess.call([clang, "-fno-inline", "-O3", "-isysroot", f"{sysroot}"] + arguments)
    else:
        subprocess.call([clang, "-fno-inline", "-O3"] + arguments)



if __name__=="__main__":
    parser = argparse.ArgumentParser(description="Script to find patterns.")
    parser.add_argument('-cpp', "--cpp", action='store_true', help="Uses clang++ instead of clang for compilation.")
    parser.add_argument("program", type=str,
                        help="Path to the source file in which patterns will be searched.")

    args = parser.parse_args(sys.argv[1:])

    if args.cpp:
        clang = f"{llvm_bindir}/clang++"

    progsource = args.program
    sysroot = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/"
    main()