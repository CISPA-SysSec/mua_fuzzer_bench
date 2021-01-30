FROM mutation-testing-system

USER user
RUN wget https://github.com/google/AFL/archive/v2.57b.tar.gz && tar xfv v2.57b.tar.gz && mv AFL* afl
RUN cd afl && make -j && cd llvm_mode && make -j
ENV PATH="/home/user/afl/:$PATH"
ENV AFL_PATH="/home/user/afl/"
COPY tmp/lib/ /home/user/lib/
COPY eval/afl/eval.sh /home/user/eval.sh
