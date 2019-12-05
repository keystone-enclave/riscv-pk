#!/bin/bash

# This script is only for Travis test. Do not run in your local repository
echo "Starting..."
if ( $(command -v riscv64-unknown-linux-gnu-gcc > /dev/null) &&
  $(command -v riscv64-unknown-elf-gcc > /dev/null) )
then
  echo "RISCV tools are already installed"
else
  echo "Downloading Prebuilt RISC-V Toolchain... "

  # The 1.0 version expected libmpfr.so.4, modern Ubuntu has .6
  TOOL_VER=1.0
  if [[ $(ldconfig -p | grep "libmpfr.so.6") ]]; then
      echo "Downloading tools v2.0 (support for libmpfr.so.6)"
      TOOL_VER=2.0
  fi

  export RISCV=$(pwd)/riscv
  export PATH=$PATH:$RISCV/bin
  wget https://github.com/keystone-enclave/firesim-riscv-tools-prebuilt/archive/${TOOL_VER}.tar.gz
  tar -xzvf ${TOOL_VER}.tar.gz
  cd firesim-riscv-tools-prebuilt-${TOOL_VER}
  ./installrelease.sh > riscv-tools-install.log
  mv distrib riscv
  cp -R riscv ../
  cd ..
  echo "Toolchain has been installed in $RISCV"
fi

if (llvm-as --version | grep "LLVM version 9") >/dev/null ;
then
    echo "LLVM 9 already installed"
else
    echo "Downloading Prebuilt LLVM 9 Tools... "
    
    LLVM_XZ='clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-16.04'
    wget 'http://releases.llvm.org/9.0.0/' ${LLVM_XZ}.tar.xz
    tar -xvf ${LLVM_XZ}.tar.xz

    mv ${LLVM_XZ} llvm-9
    rm -rf ${LLVM_XZ}.tar.xz

    echo "LLVM 9 has been installed in $(pwd)/llvm-9"
fi
