FROM mutation-testing-fuzzer-system

USER user
RUN wget https://github.com/AFLplusplus/AFLplusplus/archive/3.14c.tar.gz && tar xfv 3.14c.tar.gz && mv AFLplusplus* AFLplusplus
RUN cd AFLplusplus && make -j
ENV PATH="/home/user/AFLplusplus/:$PATH"
COPY tmp/lib/ /home/user/lib/
COPY eval/aflpp_asan/eval.sh /home/user/eval.sh
COPY eval/aflpp_main.cc /home/user/aflpp_main.cc
COPY eval/aflpp_minimize.sh /home/user/minimize.sh
