#!/usr/bin/env bash

set -Eeuxo pipefail

# based on:
# https://github.com/GNUAspell/aspell-fuzz/blob/fa4aa32c6bf9573801a7675137e1c31b9f13247f/ossfuzz.sh

mkdir -p $OUT
mkdir -p $WORK

# This script is called by the oss-fuzz main project when compiling the fuzz
# targets. This script is regression tested by travisoss.sh.

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
export ASPELL_PREFIX=$OUT/deps
export DICT_DIR=$OUT/dict

if [[ ! -d ${DICT_DIR} ]]
then
    mkdir -p ${DICT_DIR}
fi

export CFLAGS="$CFLAGS -g"
export CXXFLAGS="$CXXFLAGS -g"

echo "CC: $CC"
echo "CXX: $CXX"
echo "LIB_FUZZING_ENGINE: $LIB_FUZZING_ENGINE"
echo "CFLAGS: $CFLAGS"
echo "CXXFLAGS: $CXXFLAGS"
echo "OUT: $OUT"

export MAKEFLAGS+="-j$(nproc)"

# Install dependencies
apt-get -y install \
    automake \
    autopoint \
    bzip2 \
    gettext \
    libtool \
    texinfo \
    wget

# Compile and install libaspell.
pushd $SRC/aspell
export LIBS="-lpthread -ldl"
./autogen
./configure \
    --enable-static \
    --disable-shared \
    --disable-pspell-compatibility \
    --prefix=$ASPELL_PREFIX \
    --enable-pkgdatadir=$DICT_DIR \
    --enable-pkglibdir=$DICT_DIR

make V=1
make install
popd

# Compile the fuzzer.
autoreconf -i
./configure --with-aspell=$ASPELL_PREFIX
make V=1

# Copy the fuzzer and corpus to the output directory.
cp -v aspell_fuzzer $OUT/
# zip $OUT/aspell_fuzzer_seed_corpus.zip aspell_fuzzer_corpus/*

# Install some dictionaries!
export PATH=$ASPELL_PREFIX/bin:$PATH

install_language() {
    LANG=$1
    DICT=$2
    pushd /tmp
    wget -O- https://ftp.gnu.org/gnu/aspell/dict/${LANG}/$DICT.tar.bz2 | tar xfj -
    pushd $DICT
    ./configure
    make install
    popd
    popd
}

install_language en aspell6-en-2016.11.20-0
install_language pt_BR aspell6-pt_BR-20131030-12-0

# Verify that one corpus input runs.
echo "Running a single corpus input"
FUZZ_VERBOSE=yes $OUT/aspell_fuzzer aspell_fuzzer_corpus/en_us_input_utf8

get-bc $OUT/aspell_fuzzer

ls -la $OUT
ls -la $WORK

