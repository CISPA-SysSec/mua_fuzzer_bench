FROM mutation-testing-fuzzer-system

USER user
RUN wget https://github.com/google/AFL/archive/v2.57b.tar.gz && tar xfv v2.57b.tar.gz && mv AFL* afl
RUN cd afl && make -j && cd llvm_mode && make -j
ENV PATH="$PATH:/home/user/afl/"
ENV AFL_PATH="/home/user/afl/"
COPY tmp/lib/ /home/user/lib/
COPY dockerfiles/programs/common/ /home/user/common/
COPY dockerfiles/fuzzers/afl/eval.sh /home/user/eval.sh
COPY dockerfiles/fuzzers/afl/minimize.sh /home/user/minimize.sh
