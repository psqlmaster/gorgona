# Building Gorgona for OpenWrt

This guide explains how to cross-compile **Gorgona** for OpenWrt devices.

## Prerequisites

- A working OpenWrt build system for your target device
- Basic familiarity with the command line and OpenWrt toolchain

## Build Steps

### 1. Build OpenWrt for your device

First, set up the OpenWrt build system for your specific device. Follow the official guide:

🔗 [OpenWrt Build System – Using the Toolchain](https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem)

Example directory structure used in this guide:

`~/crosscompile/openwrt`

### 2. Clone the Gorgona repository

```bash
git clone https://github.com/psqlmaster/gorgona.git
cd gorgona
```

### 3. Replace the Makefile

Replace the existing `Makefile` with the provided OpenWrt-specific Makefile.

Important: After replacing, edit the Makefile and update the following variables to match your environment: `OPENWRT_DIR`, `TOOLCHAIN_DIR` and `INCLUDE_DIR`

### 4. Build Gorgona

Run the standard make command:

```bash
make
```

### Output

After a successful build, you will get the following binaries ready for OpenWrt:

* `gorgona`
* `gorgonad`


