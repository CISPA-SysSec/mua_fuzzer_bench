FROM mutation-testing-fuzzer-system

RUN wget https://github.com/llvm/llvm-project/archive/llvmorg-11.1.0-rc1.tar.gz && \
    tar xfv llvmorg-11.1.0-rc1.tar.gz && mv llvm-project* llvm-project
COPY tmp/lib/ /home/user/lib/
COPY eval/libfuzzer/eval.sh /home/user/eval.sh
