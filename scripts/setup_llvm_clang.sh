#!/lib/bash -
# This is a helper script to download and build the correct version of llvm+clang
# for the project. It should work on most Linux and MacOSX.

die() {
    echo "error: $1" >&2
    exit 1
}

die_git() {
    git rm "$2" > /dev/null 2>&1
    echo "error: $1" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        die "required command not found: '$1'"
    fi
}

need_cmd mkdir
need_cmd git
need_cmd gcc
need_cmd cmake
need_cmd ninja

LLVM_VER=901
LLVM_URL=https://llvm.org/svn/llvm-project

TOOLCHAIN_DIR=${HOME}/toolchains
TOOLCHAIN_BLD=${TOOLCHAIN_DIR}/build
TOOLCHAIN_NAME=llvm+clang-${LLVM_VER}-$(gcc -dumpmachine)

SRC_DIR=${TOOLCHAIN_BLD}/${TOOLCHAIN_NAME}
BLD_DIR=${TOOLCHAIN_BLD}/${TOOLCHAIN_NAME}_build
INSTALL_DIR=${TOOLCHAIN_DIR}/${TOOLCHAIN_NAME}
# add gradle property 
echo "llvmBinPath=${BLD_DIR}/bin/" > ../gradle.properties

# get modules
if [ -d "$SRC_DIR" ]; then
  ### Take action if $DIR exists ###
  echo "${SRC_DIR} already exists, assuming LLVM and Clang to be downloaded already. If not, please delete ${SRC_DIR} and restart this script. Trying now to build LLVM and Clang ..."
else
  ###  Control will jump here if $DIR does NOT exists ###
  mkdir -p "${SRC_DIR}"
  git clone https://github.com/llvm/llvm-project.git "${SRC_DIR}" || die_git "unable to get llvm git repository"  "${SRC_DIR}"
  git checkout f47f4c137b930029bccc0ff5c0b8feb567d83e4a
fi


# configure build
export CMAKE_C_FLAGS=" -pthread -lpthread -ldl"
export LD_FLAGS=" -pthread -lpthread -ldl"
export CMAKE_CXX_FLAGS=" -pthread -lpthread -ldl"
mkdir -p "${BLD_DIR}"
cd "${BLD_DIR}" && cmake -G "Ninja"                              \
                         -Wno-dev                                \
                         -DCMAKE_BUILD_TYPE=Release              \
                         -DLLVM_DYLIB_EXPORT_ALL=ON              \
                         -DLLVM_TARGETS_TO_BUILD="host"          \
                         -DLLVM_TARGET_ARCH="host"               \
                         -DBUILD_SHARED_LIBS=ON                  \
                         -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" \
                         -DLLVM_INCLUDE_TESTS=Off                \
                         -DLLVM_ENABLE_PROJECTS='clang'          \
                         "${SRC_DIR}/llvm"

# build llvm and clang
# CMAKE_C_FLAGS:-pthread
# CMAKE_CXX_FLAGS:-pthread
cmake --build "${BLD_DIR}"                  || die "unable to build llvm/clang"
cmake --build "${BLD_DIR}" --target install || die "unable to install llvm/clang"
