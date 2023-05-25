FROM mutator_mutator

################################################################################
# woff2
WORKDIR /home/mutator/sample

# clone
RUN apt-get install -y make autoconf automake libtool
RUN git clone https://github.com/google/woff2
WORKDIR /home/mutator/sample/woff2/
RUN git checkout 4721483ad780ee2b63cb787bfee4aa64b61a0446
RUN git submodule update --init --recursive

# build
WORKDIR /home/mutator/sample
COPY woff2_harness woff2_harness
RUN CC=gclang CXX=gclang++ CFLAGS="-g -O2" CXXFLAGS="-g -O2" \
    SRC="/home/mutator/sample/woff2" \
    WORK="/home/mutator/sample/woff2/work" \
    OUT="/home/mutator/sample/woff2/out" \
    ./woff2_harness/build.sh

