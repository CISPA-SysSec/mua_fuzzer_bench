FROM mutation-testing-fuzzer-system

RUN wget https://github.com/llvm/llvm-project/archive/llvmorg-11.1.0-rc1.tar.gz && \
    tar xfv llvmorg-11.1.0-rc1.tar.gz && mv llvm-project* llvm-project
COPY tmp/lib/ /home/user/lib/
COPY dockerfiles/fuzzers/libfuzzer/eval.sh /home/user/eval.sh
COPY dockerfiles/fuzzers/libfuzzer/minimize.sh /home/user/minimize.sh
