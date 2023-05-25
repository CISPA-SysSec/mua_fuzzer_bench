FROM mutator_mutator

################################################################################
# re2
WORKDIR /home/mutator/sample
RUN git clone https://github.com/google/re2.git re2-code
WORKDIR /home/mutator/sample/re2-code
RUN git checkout 58141dc9c92189ed8d046f494f5e034d5db91bea
WORKDIR /home/mutator/sample
COPY re2_harness re2_harness
RUN CFLAGS="-g -O2" CXXFLAGS="-g -O2" \
    SRC="/home/mutator/sample/re2-code" \
    WORK="/home/mutator/sample/re2-code/work" \
    OUT="/home/mutator/sample/re2-code/out" \
    ./re2_harness/build.sh

