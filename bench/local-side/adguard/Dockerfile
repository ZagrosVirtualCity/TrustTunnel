# syntax=docker/dockerfile:1
FROM bench-ls

ARG CONAN_VER=1.54
ARG GOLANG_VER=1.18.3
ARG LLVM_MAJOR_VER=14

ARG VPN_LIBS_DIR=vpn-libs
ARG NLC_URL="https://github.com/AdguardTeam/NativeLibsCommon.git"
ARG DNS_LIBS_URL="https://github.com/AdguardTeam/DnsLibs.git"

RUN arch=$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/) && \
    apt install -y iptables ninja-build && \
    pip install conan~=$CONAN_VER && \
    ## Install LLVM
    curl -O https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh $LLVM_MAJOR_VER && \
    rm ./llvm.sh && \
    apt install -y libc++-${LLVM_MAJOR_VER}-dev && \
    ln -s libc++abi.so.1 /usr/lib/llvm-$LLVM_MAJOR_VER/lib/libc++abi.so && \
    ## Install Go
    curl https://dl.google.com/go/go${GOLANG_VER}.linux-${arch}.tar.gz -o /tmp/go.tar.gz && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
ENV PATH="/usr/lib/llvm-$LLVM_MAJOR_VER/bin:/usr/local/go/bin:$PATH"

COPY $VPN_LIBS_DIR/scripts/bootstrap_conan_deps.py \
    $VPN_LIBS_DIR/conanfile.py \
    $VPN_LIBS_DIR/conandata.yml \
    $VPN_LIBS_DIR/conan/profiles/linux-clang \
    /tmp/bench-bootstrap/
WORKDIR /tmp/bench-bootstrap/
RUN pipreqs . && \
    pip install -r requirements.txt && \
    ./bootstrap_conan_deps.py conandata.yml $NLC_URL $DNS_LIBS_URL && \
    conan install . \
        -pr=linux-clang \
        -s compiler.version=${LLVM_MAJOR_VER} \
        -s compiler.libcxx=libc++ \
        -g=cmake \
        --build=missing && \
    rm -rf /tmp/bench-bootstrap

COPY $VPN_LIBS_DIR /bench/$VPN_LIBS_DIR
WORKDIR /bench/$VPN_LIBS_DIR/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release -G "Ninja" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_CXX_COMPILER="clang++" \
        -DCMAKE_CXX_FLAGS="-stdlib=libc++"

# fixme: for some reason certificate CN check fails with non-rust endpoint
COPY ssl_verify.patch /bench/

WORKDIR /bench/$VPN_LIBS_DIR
RUN patch -p1 < /bench/ssl_verify.patch && \
    cd build && \
    ninja standalone_client && \
    mv ./standalone_client/standalone_client /bench/

COPY entrypoint.sh /bench/

WORKDIR /bench/
ENTRYPOINT ["./entrypoint.sh"]
CMD ["endpoint_hostname", "endpoint_ip", "protocol", "mode", "socks_port_first", "socks_port_last"]
