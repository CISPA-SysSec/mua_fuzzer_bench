FROM mutator_mutator

################################################################################
# guetzli
RUN apt-get install -y libpng-dev
WORKDIR /home/mutator/sample
RUN git clone https://github.com/google/guetzli.git
WORKDIR /home/mutator/sample/guetzli
RUN git checkout 214f2bb42abf5a577c079d00add5d6cc470620d3
COPY guetzli_harness /home/mutator/sample/guetzli_harness



RUN CC=gclang CXX=gclang++ CFLAGS="-g -O2" CXXFLAGS="-g -O2" \
    /home/mutator/sample/guetzli_harness/build.sh
