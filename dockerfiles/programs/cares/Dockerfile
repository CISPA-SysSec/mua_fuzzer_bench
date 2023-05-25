FROM mutator_mutator

################################################################################
# c-ares
RUN apt-get install -y make autoconf automake libtool
WORKDIR /home/mutator/sample/

# clone
RUN git clone https://github.com/c-ares/c-ares.git
WORKDIR /home/mutator/sample/c-ares/
RUN git checkout 809d5e84f3423ab8165650d923acb0e246cbd006

# build
WORKDIR /home/mutator/sample/c-ares/
COPY c-ares_harness /home/mutator/sample/c-ares_harness
RUN CFLAGS="-g -O2" CXXFLAGS="-g -O2" \
    SRC="/home/mutator/sample/c-ares" \
    WORK="/home/mutator/sample/c-ares/work" \
    OUT="/home/mutator/sample/c-ares/out" \
    ../c-ares_harness/build.sh
