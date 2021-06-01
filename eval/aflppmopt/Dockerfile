FROM mutation-testing-fuzzer-system

USER user
RUN wget https://github.com/AFLplusplus/AFLplusplus/archive/3.0c.tar.gz && tar xfv 3.0c.tar.gz && mv AFLplusplus* AFLplusplus
RUN cd AFLplusplus && make -j
ENV PATH="/home/user/AFLplusplus/:$PATH"
COPY tmp/lib/ /home/user/lib/
COPY eval/aflppmopt/aflpp_driver.c /home/user/AFLplusplus/utils/aflpp_driver/
COPY eval/aflppmopt/eval.sh /home/user/eval.sh
