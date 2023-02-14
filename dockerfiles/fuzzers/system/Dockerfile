# based on https://github.com/AFLplusplus/AFLplusplus/blob/stable/Dockerfile
FROM ubuntu:20.04

ARG CUSTOM_USER_ID
RUN useradd -l --uid ${CUSTOM_USER_ID} -m user
# add user to sudoers file for debugging purposes
RUN echo "user:user" | chpasswd && adduser user sudo

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    automake \
    bison flex \
    build-essential \
    git \
    python3 python3-dev python3-setuptools python-is-python3 \
    libtool libtool-bin \
    libglib2.0-dev \
    wget vim jupp nano bash-completion \
    apt-utils apt-transport-https ca-certificates gnupg dialog \
    libpixman-1-dev \
    sudo \
    wget make build-essential libbfd-dev libunwind-dev git libtool libtool-bin automake bison libglib2.0-dev cmake golang curl libc-ares-dev libfreetype6-dev libarchive-dev ragel bzip2 libgss-dev subversion libgcrypt-dev autoconf-archive virtualenv libdbus-glib-1-dev libgirepository1.0-dev libturbojpeg libssh-dev libssl-dev nasm libbz2-dev libxml2-dev autoconf automake binutils-dev bison build-essential  cmake curl daemontools git libblocksruntime-dev libboost-dev libcairo2-dev libjpeg-dev liblcms2-dev liblzma-dev libopenjp2-7-dev libpng-dev libtiff-dev libtool libunwind-dev llvm-9-dev make nasm pkg-config re2c tcl wget zlib1g-dev 

RUN echo deb http://apt.llvm.org/focal/ llvm-toolchain-focal-11 main >> /etc/apt/sources.list && \
    wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - 

RUN echo deb http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu focal main >> /etc/apt/sources.list && \
    apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 1E9377A2BA9EF27F

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y gcc-10 g++-10 gcc-10-plugin-dev gcc-10-multilib \
    libc++-10-dev gdb lcov

RUN apt-get install -y clang-11 clang-tools-11 libc++1-11 libc++-11-dev \
    libc++abi1-11 libc++abi-11-dev libclang1-11 libclang-11-dev \
    libclang-common-11-dev libclang-cpp11 libclang-cpp11-dev liblld-11 \
    liblld-11-dev liblldb-11 liblldb-11-dev libllvm11 libomp-11-dev \
    libomp5-11 lld-11 lldb-11 llvm-11 llvm-11-dev llvm-11-runtime llvm-11-tools

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 0
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-10 0
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 0
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-11 0
RUN update-alternatives \
  --install /usr/lib/llvm              llvm             /usr/lib/llvm-11  20 \
  --slave   /usr/bin/llvm-config       llvm-config      /usr/bin/llvm-config-11  \
    --slave   /usr/bin/llvm-ar           llvm-ar          /usr/bin/llvm-ar-11 \
    --slave   /usr/bin/llvm-as           llvm-as          /usr/bin/llvm-as-11 \
    --slave   /usr/bin/llvm-bcanalyzer   llvm-bcanalyzer  /usr/bin/llvm-bcanalyzer-11 \
    --slave   /usr/bin/llvm-c-test       llvm-c-test      /usr/bin/llvm-c-test-11 \
    --slave   /usr/bin/llvm-cov          llvm-cov         /usr/bin/llvm-cov-11 \
    --slave   /usr/bin/llvm-diff         llvm-diff        /usr/bin/llvm-diff-11 \
    --slave   /usr/bin/llvm-dis          llvm-dis         /usr/bin/llvm-dis-11 \
    --slave   /usr/bin/llvm-dwarfdump    llvm-dwarfdump   /usr/bin/llvm-dwarfdump-11 \
    --slave   /usr/bin/llvm-extract      llvm-extract     /usr/bin/llvm-extract-11 \
    --slave   /usr/bin/llvm-link         llvm-link        /usr/bin/llvm-link-11 \
    --slave   /usr/bin/llvm-mc           llvm-mc          /usr/bin/llvm-mc-11 \
    --slave   /usr/bin/llvm-nm           llvm-nm          /usr/bin/llvm-nm-11 \
    --slave   /usr/bin/llvm-objdump      llvm-objdump     /usr/bin/llvm-objdump-11 \
    --slave   /usr/bin/llvm-ranlib       llvm-ranlib      /usr/bin/llvm-ranlib-11 \
    --slave   /usr/bin/llvm-readobj      llvm-readobj     /usr/bin/llvm-readobj-11 \
    --slave   /usr/bin/llvm-rtdyld       llvm-rtdyld      /usr/bin/llvm-rtdyld-11 \
    --slave   /usr/bin/llvm-size         llvm-size        /usr/bin/llvm-size-11 \
    --slave   /usr/bin/llvm-stress       llvm-stress      /usr/bin/llvm-stress-11 \
    --slave   /usr/bin/llvm-symbolizer   llvm-symbolizer  /usr/bin/llvm-symbolizer-11 \
    --slave   /usr/bin/llvm-tblgen       llvm-tblgen      /usr/bin/llvm-tblgen-11

RUN rm -rf /var/cache/apt/archives/*

USER user
WORKDIR /home/user

RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/compiler-rt-11.1.0.src.tar.xz -O compiler-rt.tar.xz && ls -lah && tar xfv compiler-rt.tar.xz

RUN cd ~; git clone https://github.com/google/fuzzer-test-suite.git fuzzer-test-suite
COPY --chown=user:user dockerfiles/fuzzers/system/build.sh /home/user/fuzzer-test-suite/
COPY --chown=user:user dockerfiles/fuzzers/system/common.sh /home/user/fuzzer-test-suite/
RUN chmod +x /home/user/fuzzer-test-suite/build.sh /home/user/fuzzer-test-suite/common.sh 