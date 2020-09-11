import subprocess
import sys
import os
import shutil
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import cpu_count

llvm_bindir = "@LLVM_BINDIR@"
clang = f"{llvm_bindir}/clang"
opt = f"{llvm_bindir}/opt"
mutatorplugin = "@MUTATOR_PLUGIN@"

sysroot = ""
progsource = None
uname = os.uname()


def main():
    # "${CLANG}" -g -S -D_FORTIFY_SOURCE=0 "${SYSROOT}" -emit-llvm -include "${INCDIR}/traceinstr/wrapper_libc.h" -o "${PROG_SOURCE}.uninstrumented.bc" -x c "${PROG_SOURCE}"
    # Macos catalina and newer need sysroot to be defined when compiling
    # TODO also check for actual version, not only if macos or not
    # "${LLVM}/opt" -S -instnamer -reg2mem -load "${TRACEPLUGIN}" -traceplugin -exclude_functions "${EXCLUDED_FUNCTIONS}" -disable-verify "${PROG_SOURCE}.uninstrumented.bc" -o  "${PROG_SOURCE}.opt_debug.bc"

    counter = 0
    basepath = os.path.dirname(progsource)
    mutations_folder = os.path.join(basepath, "mutations")
    progname = os.path.basename(progsource)
    print(f"[INFO] Folder to put mutations into: {mutations_folder}")
    shutil.rmtree(mutations_folder, ignore_errors=True)
    os.makedirs(mutations_folder)
    with open(f"{progsource}.mutationlocations") as mutations:
        mutation_list = []
        for el in mutations.readlines():
            mutation_list.append((counter, el, mutations_folder, progname))
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
    mutation = information[1]
    mutations_folder = information[2]
    progname = information[3]
    print(f"[INFO] Mutating {mutation[:-1]} to file {mutations_folder}/{progname}.{counter}.mut\n")
    with open(f"{progsource}.ll") as progsource_file:
        subprocess.call([opt, "-S", "-load", mutatorplugin, "-mutatorplugin", "-mutation_pattern", mutation[:-1],  "-disable-verify", "-o", f"{mutations_folder}/{progname}.{counter}.mut.ll"], stdin=progsource_file)

    if uname.sysname == "Darwin":
        subprocess.call([clang, "-fno-inline", "-O3", "-isysroot", f"{sysroot}", "-o", f"{mutations_folder}/{progname}.{counter}.mut", f"{mutations_folder}/{progname}.{counter}.mut.ll", "-lm", "-lz", "-ldl"])
    else:
        subprocess.call([clang, "-fno-inline", "-O3", "-o", f"{mutations_folder}/{progname}.{counter}.mut", f"{mutations_folder}/{progname}.{counter}.mut.ll", "-lm", "-lz", "-ldl"])


if __name__ == "__main__":
    if len(sys.argv) > 1:
        progsource = sys.argv[1]
        sysroot = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/"
        main()
    else:
        raise FileExistsError("Input C file is missing.")