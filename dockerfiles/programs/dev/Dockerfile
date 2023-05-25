FROM mutator_mutator

################################################################################
WORKDIR /home/mutator/sample/

# build
COPY dev_harness/ dev_harness/
RUN CFLAGS="-g -O2" CXXFLAGS="-g -O2" \
    SRC="/home/mutator/sample/" \
    WORK="/home/mutator/sample/work" \
    OUT="/home/mutator/sample/out" \
    dev_harness/build.sh