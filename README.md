TinyEMU-virtio
==============

TinyEMU-virtio contains the virtio hosting component
of [TinyEMU](https://bellard.org/tinyemu/) packaged as a library.

We use it to provide I/O peripherals to RISC-V processors implemented in FPGAs.

See [ssith-aws-fpga](https://github.com/acceleratdtech/ssith-aws-fpga) for an
example of a complete RISC-V processor that uses TinyEMU-virtio.


Compile options
---------------

There are a few options which can be enabled at compile time using #define flags.

- `CONFIG_FS_NET` is likely obsolete, but used to enable some sort of remote filesystem. It is on by default when libcurl dev dependencies are present.
- `CONFIG_SLIRP` enables the emulated virtio network device to connect to the host system through SLIRP. I (sws35) don't know how to connect to SLIRP through the host. It is on by default.
- `CONFIG_TUN` enables the emulated virtio network device to connect to the host system through a tun/tap. It uses the Linux tun/tap headers and will not work on FreeBSD or Windows. It is off by default.
