import subprocess
import sys
import os
import shutil
import json
import shlex
from pathlib import Path
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import cpu_count
import argparse

llvm_bindir = "@LLVM_BINDIR@"
opt = f"{llvm_bindir}/opt"
mutatorplugin = "@MUTATOR_PLUGIN@"
dynamic_libraries_folder = "@DYN_LIB_FOLDER@"
linked_libraries = "dynamiclibrary"
is_cpp = False

sysroot = ""
uname = os.uname()


def mutate_file(args):
    """
    Mutates one file with the given information.
    :param information: A tuple containing the following information:
        counter, mutation, folder to put result in, name of program to mutate,
    :return:
    """
    # mutation contains each line that has been read from the mutationLocations file
    mutation, out_dir, progsource, progname, sysroot, clang, args = args
    bc_args = shlex.split(args.bc_args)
    bin_args = shlex.split(args.bin_args)

    # Macos catalina and newer need sysroot to be defined when compiling
    # According to https://en.wikipedia.org/wiki/Darwin_%28operating_system%29#Release_history,
    # MacOS Catalina corresponds to Darwin's major version number 19.
    # The uname.release checks below check if the major version number of Darwin is greater than 18
    mut_bin = Path(f"{out_dir}/{progname}.mut")
    assert not mut_bin.exists(), f"The output file already exists, aborting: {mut_bin}"
    mut_bin = str(mut_bin)

    print(f"[INFO] Mutating {mutation} to file {mut_bin}\n")
    with open(f"{progsource}.ll") as progsource_file:
        sp_call_args = [opt, "-S", "-load", mutatorplugin, "-mutatorplugin",
                         "-mutation_pattern", json.dumps(mutation), "-disable-verify", "-o",
                        f"{mut_bin}.ll"]
        if is_cpp:
            sp_call_args.append("-cpp")

        subprocess.call(sp_call_args, stdin=progsource_file)

    if args.bitcode:
        if uname.sysname == "Darwin" and int(uname.release.split('.')[0]) >= 19:
            subprocess.call([clang, "-emit-llvm", "-fno-inline", "-O3", "-isysroot",
                             f"{sysroot}", *bc_args,
                             "-c", f"{mut_bin}.ll",
                             "-o", f"{mut_bin}.bc"])
        else:
            subprocess.call([clang, "-emit-llvm", "-fno-inline", "-O3", *bc_args,
                             "-c", f"{mut_bin}.ll",
                             "-o", f"{mut_bin}.bc"])

    if args.binary:
        arguments = [
            # "-v",
            f"{mut_bin}.ll",  # input file
            *bc_args, *bin_args,
            f"-L{dynamic_libraries_folder}",  # points the runtime linker to the location of the included shared library
            "-lm", "-lz", "-ldl",  # some often used libraries
            f"-l{linked_libraries}",  # the library containing all the api functions that were called by mutations
            "-o", f"{mut_bin}",  # output file
        ]
        if uname.sysname == "Darwin" and int(uname.release.split('.')[0]) >= 19:
            subprocess.call([clang, "-fno-inline", "-O3", "-isysroot", f"{sysroot}"] + arguments)
        else:
            subprocess.call([clang, "-fno-inline", "-O3"] + arguments)

    if not args.bitcode_human_readable:
        os.remove(f"{mut_bin}.ll")


def mutate(sysroot, clang, args):
    # "${CLANG}" -g -S -D_FORTIFY_SOURCE=0 "${SYSROOT}" -emit-llvm -include "${INCDIR}/traceinstr/wrapper_libc.h" -o "${PROG_SOURCE}.uninstrumented.bc" -x c "${PROG_SOURCE}"
    # "${LLVM}/opt" -S -instnamer -reg2mem -load "${TRACEPLUGIN}" -traceplugin -exclude_functions "${EXCLUDED_FUNCTIONS}" -disable-verify "${PROG_SOURCE}.uninstrumented.bc" -o  "${PROG_SOURCE}.opt_debug.bc"
    prog = args.program

    basepath = os.path.dirname(prog)
    if args.out_dir == "":
        mutations_folder = os.path.join(basepath, "mutations")
    else:
        mutations_folder = args.out_dir
    progname = os.path.basename(prog)
    print(f"[INFO] Folder to put mutations into: {mutations_folder}")
    shutil.rmtree(mutations_folder, ignore_errors=True)
    os.makedirs(mutations_folder)
    with open(f"{prog}.mutationlocations") as mutations:
        mutation_list = []
        mutation_jsondata = json.load(mutations)
        # if args.mutate is -1 then all mutation files should be created, otherwise just the one with the defined id
        if args.mutate == -1:
            for mutation in mutation_jsondata:
                mutation_list.append((mutation, mutations_folder, prog, progname, sysroot, clang, args))
        elif args.mutate != -2:
            for mutation in mutation_jsondata:
                if mutation["UID"] == args.mutate:
                    mutation_list.append((mutation, mutations_folder, prog, progname, sysroot, clang, args))
                    break
        elif args.mutatelist:
            tmplist = []
            for mutation in mutation_jsondata:
                if mutation["UID"] in args.mutatelist:
                    tmplist.append(mutation)
            mutation_list.append((tmplist, mutations_folder, prog, progname, sysroot, clang, args))
        else:
            print("Neither mutation ID nor mutation given, please define what to mutate!")
        # TODO later this will get logged to have for each id the correct pattern used
        if mutation_list:
            pool = ThreadPool(cpu_count())
            pool.map(mutate_file, mutation_list)
        else:
            raise LookupError(f"Could not find mutation with id {args.mutate} in file {prog}.mutationlocations")


def main():
    parser = argparse.ArgumentParser(description="Mutator Script. Need at least \
                one of the arguments [-bc, -ll, -bn] to get resulting files.")
    parser.add_argument('-bc', "--bitcode", action='store_true',
                        help="Keeps the mutated bitcode files.")
    parser.add_argument('-ll', "--bitcode_human_readable", action='store_true',
                        help="Keeps the mutated bitcode files as human readable files.")
    parser.add_argument('-bn', "--binary", action='store_true',
                        help="Creates mutated runnable binaries.")

    compiler = parser.add_mutually_exclusive_group(required=True)
    compiler.add_argument('-cc', "--cc", action='store_true', help="Uses clang for compilation.")
    compiler.add_argument('-cpp', "--cpp", action='store_true', help="Uses clang++ for compilation.")

    parser.add_argument("-m", "--mutate", type=int, default=-2,
                        help="Defines which mutation should be applied, -1 if all should be applied.")
    parser.add_argument("-ml", "--mutatelist", type=int, nargs="*", default=[],
                        help="Defines which mutations should be applied, a sequence of integers: -ml 1 2 3")
    parser.add_argument("--bc-args", default="",
                        help="Compiler arguments that should be used for compilation for all artifacts.")
    parser.add_argument("--bin-args", default="",
                        help="Compiler arguments that should be used for compilation of the binary.")
    parser.add_argument("--out-dir", type=str, default="",
                        help="Path to output directory, where artifacts will be written to.")
    parser.add_argument("program", type=str,
                        help="Path to the source file that will be mutated.")

    args = parser.parse_args(sys.argv[1:])

    if not any([args.bitcode, args.bitcode_human_readable, args.binary]):
        parser.error('Need at least one of the arguments [-bc, -ll, -bn] to get resulting files.')

    if args.mutate != -2 and not args.mutatelist:
        parser.error("Either mutate or mutatelist can be activated, not both.")

    if args.cpp:
        clang = f"{llvm_bindir}/clang++"
        global is_cpp
        is_cpp = True
    else:
        clang = f"{llvm_bindir}/clang"

    sysroot = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/"
    mutate(sysroot, clang, args)


if __name__ == "__main__":
    main()

