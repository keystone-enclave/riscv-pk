RISC-V Proxy Kernel and Boot Loader + Keystone SM
=================================================

About
---------

The RISC-V Proxy Kernel, `pk`, is a lightweight application execution
environment that can host statically-linked RISC-V ELF binaries.  It is
designed to support tethered RISC-V implementations with limited I/O
capability and and thus handles I/O-related system calls by proxying them to
a host computer.

This package also contains the Berkeley Boot Loader, `bbl`, which is a
supervisor execution environment for tethered RISC-V systems.  It is
designed to host the RISC-V Linux port.

This also contains the Keystone Security Monitor (SM) in `sm`.

Build Steps
---------------

We suggest building the bbl image using the top-level build in
[keystone](https://github.com/keystone-enclave/keystone).

If you wish to build the bbl independently, either:
follow the build instructions
[here](http://docs.keystone-enclave.org/en/dev/Getting-Started/Running-Keystone-with-QEMU.html#build-berkeley-bootloader-bbl-with-keystone-security-monitor)
or follow the flow in the Makefile in
[keystone](https://github.com/keystone-enclave/keystone).

The top-level Makefile will always be the most up-to-date build
instructions.

Test
--------------

Make sure that `qemu-riscv64` is in your PATH.
`qemu-riscv64` can be compiled from the upstream [qemu source](https://github.com/qemu/qemu) v4.0.0 (try `./configure --target-list=riscv64-linux-user`).

Current test only covers the security monitor, and exists as a separate build system.

```
cd sm/tests
mkdir build; cd build
cmake ..
make
```

... and run tests!

```
make test
```

To see the why your test fails the test, you should try

```
make test CTEST_OUTPUT_ON_FAILURE=TRUE
```
