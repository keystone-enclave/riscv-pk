#!/bin/bash

# This script is only for Travis test. Do not run in your local repository
git clone --shallow-since=2018-05-01 https://github.com/qemu/qemu riscv-qemu
cd riscv-qemu; git checkout v4.0.0; cd ..
cd riscv-qemu; ./configure --target-list=riscv64-linux-user; make -j$(nproc); cd ..
mkdir -p riscv
cp riscv-qemu/riscv64-linux-user/qemu-riscv64 ./riscv
