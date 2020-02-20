#!/bin/bash
set -e

mkdir -p test-build
cd test-build

if [ ! -f Makefile ]; then
	../configure --host=riscv64-unknown-linux-gnu --enable-sm_rs
fi
make -j12 RUST_TARGET=../riscv64gc-unknown-none-elfhf.json

export RUSTFLAGS="-Z pre-link-arg=-L$(pwd) -Z pre-link-arg=-lsm_rs_Clib -C link-arg=-Wl,--start-group -C link-arg=-lmachine -C link-arg=-lutil -C link-arg=-lsm_rs_Clib -C link-arg=-Wl,--end-group"
export CFLAGS='-DTARGET_PLATFORM_HEADER="platform/default/default.h"'
cargo +nightly xtest --target-dir sm_rs/ --target ../riscv64gc-unknown-linux-gnuhf.json --manifest-path=../sm_rs/Cargo.toml

