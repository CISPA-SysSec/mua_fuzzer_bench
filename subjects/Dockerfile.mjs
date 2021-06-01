FROM mutator_mutator

################################################################################
# mjs
WORKDIR /home/mutator/samples
RUN git clone https://github.com/cesanta/mjs.git
WORKDIR /home/mutator/samples/mjs/mjs
RUN git checkout 2.19.1
COPY samples/mjs_harness /home/mutator/samples/mjs_harness
RUN make mjs.c
RUN gclang -g -O2 -DMJS_MAIN -ldl -o mjs mjs.c
RUN get-bc mjs
WORKDIR /home/mutator

