#!/bin/bash

mkdir -p test-build
cd test-build

if [ ! -f Makefile ]; then
	../configure --host=riscv64-unknown-linux-gnu --enable-sm
fi
CFLAGS='-mabi=lp64' make -j12

export RUSTFLAGS="-Z pre-link-arg=-L$(pwd) -Z pre-link-arg=-lsm -C link-arg=-Wl,--start-group -C link-arg=-lmachine -C link-arg=-lsoftfloat -C link-arg=-lutil -C link-arg=-lsm -C link-arg=-Wl,--end-group -C link-arg=-lc -C link-arg=-lgcc"
export CFLAGS='-DTARGET_PLATFORM_HEADER="platform/default/default.h"'
cargo xbuild --tests --target-dir sm_rs/ --target ../riscv64gc-linux-gnu.json --manifest-path=../sm/Cargo.toml

OUT_DIR=sm_rs/riscv64gc-linux-gnu/debug/
NUM_TESTS=$(ls $OUT_DIR/sm_rs-* -1 | wc -l)
if [ "$NUM_TESTS" = "1" ]; then
	rm $OUT_DIR/sm_rs-*
	cd ..
	./test-sm.sh
else
	../../riscv-qemu/riscv64-linux-user/qemu-riscv64 $OUT_DIR/sm_rs-*
fi
