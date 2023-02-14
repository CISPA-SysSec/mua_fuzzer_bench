FROM mutation-testing-fuzzer-system

USER user
RUN wget https://github.com/AFLplusplus/AFLplusplus/archive/3.14c.tar.gz && tar xfv 3.14c.tar.gz && mv AFLplusplus* AFLplusplus
RUN cd AFLplusplus && make -j
ENV PATH="/home/user/AFLplusplus/:$PATH"
COPY tmp/lib/ /home/user/lib/
COPY dockerfiles/fuzzers/aflpp/eval.sh /home/user/eval.sh
COPY dockerfiles/fuzzers/aflpp_main.cc /home/user/aflpp_main.cc
COPY dockerfiles/fuzzers/aflpp/minimize.sh /home/user/minimize.sh
