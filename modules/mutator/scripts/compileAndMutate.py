import subprocess
import sys
import os

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
    if (uname.sysname=="Darwin"):
        # if (uname["release"]):
        subprocess.call([clang, "-g", "-S", "-D_FORTIFY_SOURCE=0", "-isysroot", f"{sysroot}", "-emit-llvm", "-o", f"{progsource}.ll", "-x", "c", progsource])
    else:
        subprocess.call([clang, "-g", "-S", "-D_FORTIFY_SOURCE=0", "-emit-llvm", "-o", f"{progsource}.ll", "-x", "c", progsource])

    # "${LLVM}/opt" -S -instnamer -reg2mem -load "${TRACEPLUGIN}" -traceplugin -exclude_functions "${EXCLUDED_FUNCTIONS}" -disable-verify "${PROG_SOURCE}.uninstrumented.bc" -o  "${PROG_SOURCE}.opt_debug.bc"

    with open(f"{progsource}.ll", "r") as progsource_file:
        subprocess.call([opt, "-S", "-load", mutatorplugin, "-mutatorplugin", "-mutation_patterns", "/dev/null",  "-disable-verify", "-o", f"{progsource}.opt_mutate.ll"], stdin=progsource_file)

    subprocess.call([clang, "-fno-inline", "-O3", "-isysroot", f"{sysroot}", "-o", f"{progsource}.mutated" ,f"{progsource}.opt_mutate.ll" ,"-lm" ,"-lz", "-ldl"])

if __name__=="__main__":
    if len(sys.argv) > 1:
        progsource = sys.argv[1]
        sysroot = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/"
        main()
    else:
        pass
        # TODO raise error