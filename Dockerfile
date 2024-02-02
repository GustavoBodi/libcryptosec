FROM ubuntu:22.04
RUN apt update; apt -y upgrade; apt -y autoclean; apt -y autoremove 
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt -y install git wget gcc g++ gdb make vim libgtest-dev pkgconf
RUN mkdir -p /home/labsec/

RUN cd /home/labsec/ \
    && wget --no-check-certificate https://ftp.openssl.org/source/old/3.0/openssl-3.0.11.tar.gz \
    && tar -xvf openssl-3.0.11.tar.gz \
    && cd openssl-3.0.11/ \
    && ./config shared -Wl,-rpath -Wl,/usr/local/ssl/lib64 -L/usr/local/ssl/lib64 -I/usr/local/ssl/include --openssldir=/usr/local/ssl --prefix=/usr/local/ssl \
    && make \
    && make install

ENV LIBP11_PREFIX=/usr/local
ENV LIBP11_LIBDIR=$LIBP11_PREFIX/lib
ENV LIBP11_INCLUDEDIR=$LIBP11_PREFIX/include
ENV INSTALL_PREFIX=/usr/local
ENV INSTALL_LIBDIR=$INSTALL_PREFIX/lib64

RUN cd /home/labsec/ \
    && wget --no-check-certificate https://github.com/OpenSC/libp11/releases/download/libp11-0.4.7/libp11-0.4.7.tar.gz \
    && tar -xvf libp11-0.4.7.tar.gz \
    && cd libp11-0.4.7/ \
    && export OPENSSL_CFLAGS=-I/usr/local/ssl/include \
    && export OPENSSL_LIBS="-Wl,-rpath -Wl,/usr/local/ssl/lib64 -L/usr/local/ssl/lib64 -lcrypto -ldl" \
    && ./configure \
    && make -j12 \
    && make install

COPY . /home/labsec/libcryptosec

RUN cd /home/labsec/libcryptosec/ && \
    make -j12 && \
    make install

RUN cd /home/labsec/libcryptosec/tests && \
    make -j12

WORKDIR /home/labsec/libcryptosec/tests

RUN ./test.out

WORKDIR /home/labsec/libcryptosec/
