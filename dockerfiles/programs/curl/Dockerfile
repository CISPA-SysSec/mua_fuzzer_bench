FROM mutator_mutator

################################################################################
# curl
WORKDIR /home/mutator/sample

# clone
WORKDIR /home/mutator/sample/
RUN git clone https://github.com/curl/curl.git curl
RUN git -C curl checkout curl-7_83_1
RUN git clone https://github.com/curl/curl-fuzzer.git curl_fuzzer
RUN git -C curl_fuzzer checkout -f 543b9926cc322a18ad30945dc55d78dbbfa679e1

# need to hotpatch zlib URL for curl_fuzzer since the verion was archived
RUN sed -i 's/https\:\/\/www\.zlib\.net\//https\:\/\/zlib\.net\/fossils\//' curl_fuzzer/scripts/download_zlib.sh

# build
COPY curl_harness curl_harness
WORKDIR /home/mutator/sample/curl_fuzzer/
RUN CFLAGS="-g -O2" CXXFLAGS="-g -O2" \
    SRC="/home/mutator/sample/curl" \
    WORK="/home/mutator/sample/curl/work" \
    OUT="/home/mutator/sample/curl/out" \
    FUZZ_TARGETS="curl_fuzzer_http" \
    ../curl_harness/build.sh
