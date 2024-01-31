FROM ubuntu:22.04
RUN apt update; apt -y upgrade; apt -y autoclean; apt -y autoremove 
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt -y install openssl libssl-dev pkgconf
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt -y install git wget gcc g++ gdb make vim libgtest-dev
RUN mkdir -p /home/labsec/

#RUN cd /home/labsec/ \
#    && wget --no-check-certificate https://ftp.openssl.org/source/old/3.0/openssl-3.0.11.tar.gz \
#    && tar -xvf openssl-3.0.11.tar.gz \
#    && cd openssl-3.0.11/ \
#    && ./config shared -Wl,-rpath -Wl,/usr/local/ssl/lib -L/usr/local/ssl/lib -I/usr/local/ssl/include --openssldir=/usr/local/ssl --prefix=/usr/local/ssl \
#    && make \
#    && make install
#
#RUN ln -s /usr/local/ssl/lib/libcrypto.so /usr/lib/

RUN echo '\nexport OPENSSL_PREFIX=/usr/local/ssl' >> ~/.bashrc
RUN echo '\nexport OPENSSL_LIBDIR=$OPENSSL_PREFIX/lib' >> ~/.bashrc
RUN echo '\nexport LIBP11_PREFIX=/usr/local' >> ~/.bashrc
RUN echo '\nexport LIBP11_LIBDIR=$LIBP11_PREFIX/lib' >> ~/.bashrc
RUN echo '\nexport LIBP11_INCLUDEDIR=$LIBP11_PREFIX/include' >> ~/.bashrc
RUN echo '\nexport INSTALL_PREFIX=/usr' >> ~/.bashrc
RUN echo '\nexport INSTALL_LIBDIR=$INSTALL_PREFIX/lib64' >> ~/.bashrc

RUN cd /home/labsec/ \
    && wget https://github.com/OpenSC/libp11/releases/download/libp11-0.4.7/libp11-0.4.7.tar.gz \
    && tar -xvf libp11-0.4.7.tar.gz \
    && cd libp11-0.4.7/ \
    #&& export OPENSSL_CFLAGS=-I/usr/local/ssl/include \
    #&& export OPENSSL_LIBS="-Wl,-rpath -Wl,/usr/local/ssl/lib -L/usr/local/ssl/lib -lcrypto -ldl" \
    && ./configure \
    && make -j12 \
    && make install

COPY . /home/labsec/libcryptosec

RUN cd /home/labsec/libcryptosec/ && \
    #export OPENSSL_PREFIX=/usr/local/ssl && \
    #export OPENSSL_LIBDIR=$OPENSSL_PREFIX/lib && \
    #export LIBP11_PREFIX=/usr/local && \
    #export LIBP11_LIBDIR=$LIBP11_PREFIX/lib && \
    #export LIBP11_INCLUDEDIR=$LIBP11_PREFIX/include && \
    #export INSTALL_REFIX=/usr && \
    #export INSTALL_LIBDIR=$LIBP11_PREFIX/lib64 && \
    make -j12 && \
    make install

WORKDIR /home/labsec/libcryptosec
