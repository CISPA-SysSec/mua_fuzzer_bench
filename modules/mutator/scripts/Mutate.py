import subprocess
import sys
import os
import shutil
import json
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import cpu_count
import argparse

llvm_bindir = "@LLVM_BINDIR@"
clang = f"{llvm_bindir}/clang"
opt = f"{llvm_bindir}/opt"
mutatorplugin = "@MUTATOR_PLUGIN@"
dynamic_libraries_folder = "@DYN_LIB_FOLDER@"
linked_libraries = "dynamiclibrary"

sysroot = ""
progsource = None
uname = os.uname()


def main(prog: str):
    # "${CLANG}" -g -S -D_FORTIFY_SOURCE=0 "${SYSROOT}" -emit-llvm -include "${INCDIR}/traceinstr/wrapper_libc.h" -o "${PROG_SOURCE}.uninstrumented.bc" -x c "${PROG_SOURCE}"
    # Macos catalina and newer need sysroot to be defined when compiling
    # TODO also check for actual version, not only if macos or not
    # "${LLVM}/opt" -S -instnamer -reg2mem -load "${TRACEPLUGIN}" -traceplugin -exclude_functions "${EXCLUDED_FUNCTIONS}" -disable-verify "${PROG_SOURCE}.uninstrumented.bc" -o  "${PROG_SOURCE}.opt_debug.bc"

    counter = 0
    basepath = os.path.dirname(prog)
    mutations_folder = os.path.join(basepath, "mutations")
    progname = os.path.basename(prog)
    print(f"[INFO] Folder to put mutations into: {mutations_folder}")
    shutil.rmtree(mutations_folder, ignore_errors=True)
    os.makedirs(mutations_folder)
    with open(f"{prog}.mutationlocations") as mutations:
        mutation_list = []
        mutation_jsondata = json.load(mutations)
        for mutation in mutation_jsondata:
            mutation_list.append((counter, json.dumps(mutation), mutations_folder, progname))
            counter += 1
        # TODO later this will get logged to have for each id the correct pattern used
        pool = ThreadPool(cpu_count())
        pool.map(mutate_file, mutation_list)


def mutate_file(information):
    """
    Mutates one file with the given information.
    :param information: A tuple containing the following information:
        counter, mutation, folder to put result in, name of program to mutate,
    :return:
    """
    counter = information[0]
    mutation = information[1] # this contains each line that has been read from the mutationLocations file
    mutations_folder = information[2]
    progname = information[3]
    print(f"[INFO] Mutating {mutation} to file {mutations_folder}/{progname}.{counter}.mut\n")
    with open(f"{progsource}.ll") as progsource_file:
        subprocess.call([opt, "-S", "-load", mutatorplugin, "-mutatorplugin", "-mutation_pattern", mutation, "-disable-verify", "-o", f"{mutations_folder}/{progname}.{counter}.mut.ll"], stdin=progsource_file)

    if args.bitcode:
        if uname.sysname == "Darwin":
            subprocess.call([clang, "-emit-llvm", "-fno-inline", "-O3", "-isysroot", f"{sysroot}", "-o", f"{mutations_folder}/{progname}.{counter}.mut.bc", "-c", f"{mutations_folder}/{progname}.{counter}.mut.ll"])
        else:
            subprocess.call([clang, "-emit-llvm", "-fno-inline", "-O3", "-o", f"{mutations_folder}/{progname}.{counter}.mut.bc", "-c", f"{mutations_folder}/{progname}.{counter}.mut.ll"])

    if args.binary:
        arguments = [
            # "-v",
            "-o",
            f"{mutations_folder}/{progname}.{counter}.mut", # output file
            f"{mutations_folder}/{progname}.{counter}.mut.ll", # input file
            f"-L{dynamic_libraries_folder}", # points the runtime linker to the location of the included shared library
            "-lm", "-lz", "-ldl", # some often used libraries
            f"-l{linked_libraries}", # the library containing all the api functions that were called by mutations
        ]

        if uname.sysname == "Darwin":
            subprocess.call([clang, "-fno-inline", "-O3", "-isysroot", f"{sysroot}"] + arguments)
        else:
            subprocess.call([clang, "-fno-inline", "-O3"] + arguments)

    if not args.bitcode_human_readable:
        os.remove(f"{mutations_folder}/{progname}.{counter}.mut.ll")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mutator Script")
    parser.add_argument('-bc', "--bitcode", action='store_true', help="Keeps the mutated bitcode files.")
    parser.add_argument('-ll', "--bitcode_human_readable", action='store_true', help="Keeps the mutated bitcode files as human readable files.")
    parser.add_argument('-bn', "--binary", action='store_true', help="Creates mutated runnable binaries.")
    parser.add_argument('-cpp', "--cpp", action='store_true', help="Uses clang++ instead of clang for compilation.")
    parser.add_argument('-p', "--program", default="", type=str, required=True,
                        help="Path to the source file that will be mutated. Use at least one of the arguments [-bc, -ll, -bn] to get "
                             "resulting files.")
    args = parser.parse_args(sys.argv[1:])

    if not (args.bitcode or args.bitcode_human_readable or args.binary):
        raise ValueError("Use at least one of the arguments [-bc, -ll, -bn] to get resulting files.")

    if args.cpp:
        clang = f"{llvm_bindir}/clang++"

    progsource = args.program
    sysroot = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/"
    main(progsource)