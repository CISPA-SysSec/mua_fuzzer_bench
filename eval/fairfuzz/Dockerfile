FROM mutation-testing-fuzzer-system

USER user
RUN git clone https://github.com/carolemieux/afl-rb.git && cd afl-rb && git checkout e529c1f1b366
# we have to patch some weird clang segmentation fault bug 
COPY --chown=user:user eval/fairfuzz/llvm_mode/Makefile /home/user/afl-rb/llvm_mode/Makefile
# compile fairfuzz
RUN cd afl-rb && CC=clang CXX=clang++ make -j && ls && CC=clang CXX=clang++ make -j -C llvm_mode; exit 0 && ./afl-clang --version
RUN cd afl-rb && echo user | sudo -S make install
# ENV PATH="/home/user/afl-rb/:$PATH"
ENV AFL_PATH="/home/user/afl-rb/"
COPY tmp/lib/ /home/user/lib/
COPY eval/fairfuzz/eval.sh /home/user/eval.sh
COPY eval/afl_minimize.sh /home/user/minimize.sh
