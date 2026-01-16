#!/bin/bash

#Run from Root of the project
set -x
set -e


cd ./lib/qemu
mkdir -p build
cd build
../configure --prefix=/usr/local --target-list=x86_64-softmmu --enable-debug --enable-libpmem --enable-slirp
make -j$(nproc)
sudo make install
/usr/local/bin/qemu-system-x86_64 --version