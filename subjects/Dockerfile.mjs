FROM mutator_mutator

################################################################################
# mjs

# clone
WORKDIR /home/mutator/samples
RUN git clone https://github.com/cesanta/mjs.git
WORKDIR /home/mutator/samples/mjs
RUN git checkout b1b6eac6b1e5b830a5cb14f8f4dc690ef3162551

# build
COPY samples/mjs_harness /home/mutator/samples/mjs_harness
RUN CFLAGS="" CXXFLAGS="" \
    SRC="/home/mutator/samples/mjs" \
    WORK="/home/mutator/samples/mjs/work" \
    OUT="/home/mutator/samples/mjs/out" \
    ../mjs_harness/build.sh
