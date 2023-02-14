FROM mutation-testing-fuzzer-system

USER user
RUN wget https://github.com/google/honggfuzz/archive/2.4.tar.gz && tar xfv 2.4.tar.gz && mv honggfuzz* honggfuzz && cd honggfuzz && make -j && ls && ./honggfuzz --help
ENV PATH="/home/user/honggfuzz/:/home/user/honggfuzz/hfuzz_cc/:$PATH"
COPY tmp/lib/ /home/user/lib/
COPY dockerfiles/fuzzers/honggfuzz/eval.sh /home/user/eval.sh
COPY dockerfiles/fuzzers/honggfuzz/minimize.sh /home/user/minimize.sh
