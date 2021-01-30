FROM mutation-testing-system

USER user
RUN wget https://github.com/google/honggfuzz/archive/2.3.1.tar.gz && tar xfv 2.3.1.tar.gz && mv honggfuzz* honggfuzz && cd honggfuzz && make -j && ls && ./honggfuzz --help
ENV PATH="/home/user/honggfuzz/:/home/user/honggfuzz/hfuzz_cc/:$PATH"
COPY tmp/lib/ /home/user/lib/
COPY eval/honggfuzz/eval.sh /home/user/eval.sh
