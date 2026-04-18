## Gorgona Build Guide: OpenWrt (x86_64)

This guide outlines the professional cross-compilation workflow for the Gorgona Mesh Server and Client targeting **OpenWrt 23.05 (x86_64)** using a **Debian 13 (Trixie)** host.

### 1. Host Environment Configuration
Install the required build-essential tools and system headers on your Debian development machine:

```bash
sudo apt update && sudo apt install -y \
    build-essential libncurses-dev zlib1g-dev gawk \
    git gettext libssl-dev xsltproc rsync wget unzip python3
```

### 2. SDK Workspace Setup
Download and extract the official OpenWrt Software Development Kit (SDK) for the **x86_64** architecture:

```bash
mkdir -p ~/crosscompile && cd ~/crosscompile

# Download OpenWrt 23.05.4 SDK
wget https://downloads.openwrt.org/releases/23.05.4/targets/x86/64/openwrt-sdk-23.05.4-x86-64_gcc-12.3.0_musl.Linux-x86_64.tar.xz

# Extract the SDK
tar -xf openwrt-sdk-23.05.4-x86-64_gcc-12.3.0_musl.Linux-x86_64.tar.xz
```

### 3. Dependency Management (OpenSSL)
Gorgona requires `libopenssl` headers and shared objects to be present in the SDK's `staging_dir`. Follow this verified procedure to prepare the environment:

```bash
# Enter the full SDK directory
cd ~/crosscompile/openwrt-sdk-23.05.4-x86-64_gcc-12.3.0_musl.Linux-x86_64

# Update package index and download OpenSSL source
./scripts/feeds update base
./scripts/feeds install openssl

# Force package registration in the build system
# (This ensures the Makefile targets are visible to the SDK)
mkdir -p package/libs
cp -r feeds/base/package/libs/openssl package/libs/

# Generate default configuration and enable OpenSSL
echo "CONFIG_PACKAGE_libopenssl=y" >> .config
make defconfig

# Compile and stage OpenSSL (Staging installs headers to staging_dir)
# Uses all available CPU cores for high-speed compilation
make package/libs/openssl/install -j$(nproc) V=s
```

### 4. Cross-Compilation Process
Ensure your project Makefile at `OpenWrt/x86_64/Makefile` points to the correct `SDK_ROOT` path. Then, trigger the multi-version build:

```bash
cd ~/repository/c/gorgona/OpenWrt/x86_64

#Start the build
make clean && make
```

#### Verification
Confirm the generated binaries match the 64-bit target:
```bash
file gorgonad_owrt_23.05.4
#Output: ELF 64-bit LSB executable, x86-64, interpreter /lib/ld-musl-x86_64.so.1
```

### 5. Deployment and Installation
OpenWrt's default SSH server (**Dropbear**) typically lacks SFTP support. Use the legacy SCP protocol (flag `-O`) for deployment:

```bash
# Upload to the router
scp -O gorgonad_owrt_23.05.4 root@192.168.1.1:/usr/bin/gorgonad
scp -O gorgona_owrt_23.05.4 root@192.168.1.1:/usr/bin/gorgona

# SSH into the router
ssh root@192.168.1.1

# Set execution permissions and ensure dependencies are met
chmod +x /usr/bin/gorgonad /usr/bin/gorgona
opkg update && opkg install libopenssl
```

### Operational Notes and Best Practices

#### Multi-SDK Management
If you have multiple SDK versions in `~/crosscompile/`, the Gorgona Multi-SDK Makefile will automatically discover any directory matching `openwrt-sdk-*`. This allows building for 23.05, 24.10, and snapshots simultaneously while keeping binaries strictly separated by OS version suffix.

#### Database Persistence on OpenWrt
*   Default path is `/var/lib/gorgona/`. 
*   **Caution:** On OpenWrt, `/var` is typically a **tmpfs (RAM-disk)**. Data will not survive a reboot. 
*   Redirect the database to internal flash (e.g., `/etc/gorgona/db/`) or an external mount for true persistence.

#### Anti-Entropy and System Time
Embedded hardware often lacks an RTC (Real-Time Clock). 
*   **Behavior:** Snowflake IDs and Anti-Entropy synchronization rely on monotonic time. A clock reset to 1970 will break replication.
*   **Solution:** Ensure `ntpd` is synchronized before starting `gorgonad`.
    ```bash
    ntpd -n -q -p pool.ntp.org
    ```

#### Performance Metrics (Gorgona Score)
Node health is monitored via RTT and throughput. Access the diagnostic panel via `status <sync_psk>` to identify "toxic" peers. Nodes with a score below **0.05** are deprioritized by the Mesh engine.
