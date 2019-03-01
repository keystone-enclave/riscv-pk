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
