FROM mutator_mutator

################################################################################
RUN apt-get install -y make autoconf automake libtool cmake pkg-config
WORKDIR /home/mutator/sample
WORKDIR /home/mutator/sample
RUN git clone https://github.com/libevent/libevent.git libevent
WORKDIR /home/mutator/sample/libevent
RUN git checkout 5df3037d10556bfcb675bc73e516978b75fc7bc7 # release-2.1.12-stable

WORKDIR /home/mutator/sample
COPY libevent_harness libevent_harness

RUN CFLAGS="-g -O2" CXXFLAGS="-g -O2" \
    SRC="/home/mutator/sample/libevent" \
    WORK="/home/mutator/sample/libevent/work" \
    OUT="/home/mutator/sample/libevent/out" \
    ./libevent_harness/build.sh
