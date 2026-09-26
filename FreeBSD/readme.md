# Gorgona on FreeBSD / OPNsense

This directory contains the build configuration, `rc.d` service scripts, and integration examples tailored specifically for **FreeBSD** and **OPNsense** environments.

---

## Directory Overview

```text
FreeBSD/
├── Makefile       # Native GNU Make build script for FreeBSD (Clang + ports paths)
├── rc.d/          # Service script for FreeBSD's rc.d init system
│   └── gorgona    # Daemon supervisor script (/usr/local/etc/rc.d/gorgona)
├── examples/      # Real-world integration scripts
│   └── cscli_decisions_list.sh  # CrowdSec decision exporter example
└── README.md
```

---

## 1. Prerequisites

FreeBSD requires GNU Make (`gmake`) to process the project's build logic, as well as `git` for version extraction from repository tags:

```sh
pkg install -y gmake git
```

*(Clang `cc` and OpenSSL are part of the FreeBSD base system and do not require additional packages).*

---

## 2. Building from Source

Enter the `FreeBSD/` directory and compile using `gmake`:

```sh
cd FreeBSD
gmake clean && gmake
```

Upon completion, both binaries will be compiled:
- `../gorgona` (Client)
- `../gorgonad` (Server / Node)

Symlinks are also created directly inside the `FreeBSD/` directory for convenience.

---

## 3. Installation

Install the compiled binaries into the standard FreeBSD `/usr/local/bin` directory:

```sh
install -m 755 ../gorgona /usr/local/bin/gorgona
install -m 755 ../gorgonad /usr/local/bin/gorgonad
```

---

## 4. Setting up the Background Service (`rc.d`)

To run the Gorgona listener continuously as a supervised background daemon (with automatic restart on failure):

### Step 1: Install the service script
```sh
install -m 755 rc.d/gorgona /usr/local/etc/rc.d/gorgona
```

### Step 2: Enable the service in `/etc/rc.conf`
```sh
sysrc gorgona_enable="YES"
```

### Optional configuration options in `/etc/rc.conf`:
You can customize the listener flags and log location without modifying the script:

```sh
# Specify custom arguments (default: "-e listen new"):
sysrc gorgona_args="-e listen new BTW9V5jVztY="

# Specify custom configuration file:
sysrc gorgona_args="-c /usr/local/etc/gorgona/gorgona.conf -e listen new"

# Specify log file (default: /var/log/gorgona.log):
sysrc gorgona_logfile="/var/log/gorgona.log"
```

---

## 5. Service Management

Use standard FreeBSD `service` commands:

| Action | Command |
|---|---|
| **Start** | `service gorgona start` |
| **Status** | `service gorgona status` |
| **Stop** | `service gorgona stop` |
| **Restart** | `service gorgona restart` |
| **View Logs** | `tail -f /var/log/gorgona.log` |

The service uses FreeBSD's native `/usr/sbin/daemon` supervisor with the `-r` flag, guaranteeing that if the listener terminates unexpectedly, it will automatically restart.

---

## 6. Examples

The `examples/` directory contains practical integration use-cases:

- **`cscli_decisions_list.sh`**: Periodically pipes active CrowdSec security decisions into an encrypted, time-locked Gorgona alert and sends them to a recipient public key.
  Uses BSD `date -v+3d` syntax for native FreeBSD compatibility.
