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
│   ├── cscli_ban_ip.sh          # Remote IP banning with automatic response
│   └── cscli_decisions_list.sh  # CrowdSec decision exporter
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

## 6. Real-World Integration: Remote CrowdSec Firewall Remediation

Gorgona allows you to securely manage perimeter firewalls over an encrypted P2P mesh without exposing SSH ports. 

Below is an autonomous **Request-Response loop**:
1. An administrator sends a time-locked `ban <IP>` command to OPNsense via Gorgona.
2. The OPNsense daemon verifies the signature and bans the IP via `cscli`.
3. OPNsense automatically packages the updated firewall decisions table into a return alert and sends it back to the administrator.

### 6.1. Script Setup

Place the following integration scripts into `/usr/local/bin`:

#### `/usr/local/bin/cscli_ban_ip.sh`
```sh
#!/bin/sh

export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

IP="$1"
DURATION="24h"
REASON="${2:-Banned via Gorgona P2P}"

if [ -z "$IP" ]; then
    echo "[ERROR] Missing IP argument." >&2
    echo "Usage: $0 <IP_ADDRESS> [REASON]" >&2
    exit 1
fi

CSCLI=$(command -v cscli || echo "/usr/local/bin/cscli")
if [ ! -x "$CSCLI" ]; then
    echo "[ERROR] cscli not found at $CSCLI" >&2
    exit 1
fi

echo "[INFO] Adding CrowdSec decision: IP=$IP, Duration=$DURATION, Reason='$REASON'"
"$CSCLI" decisions add --ip "$IP" --duration "$DURATION" --reason "$REASON"

# Automatically send back the updated active decisions table
/usr/local/bin/cscli_decisions_list.sh
```

#### `/usr/local/bin/cscli_decisions_list.sh`
```sh
#!/bin/sh

export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

START_DATE=$(date -u '+%Y-%m-%d %H:%M:%S')
EXPIRE_DATE=$(date -u -v+3d '+%Y-%m-%d %H:%M:%S')

/usr/local/bin/cscli decisions list 2>/dev/null | \
/usr/local/bin/gorgona send "$START_DATE" "$EXPIRE_DATE" - "RWTPQzuhzBw=.pub"
```

Make both scripts executable:
```sh
chmod 755 /usr/local/bin/cscli_ban_ip.sh
chmod 755 /usr/local/bin/cscli_decisions_list.sh
```

---

### 6.2. Client Configuration (`/etc/gorgona/gorgona.conf`)

Configure the client to restrict command execution only to authorized public keys:

```ini
[server]
port = 7777
ip = 64.188.70.158
sync_psk = BQQCyN8zo4La2lRSIQ2jLp5imEa0JzdXp2PKogP3

# Paths (defaults shown below)
data_dir = /var/lib/gorgona
conf_dir = /etc/gorgona
log_file = /var/log/gorgona/gorgona.log
log_level = error

# Remote execution bindings for key hash RWTPQzuhzBw=
[exec_commands:RWTPQzuhzBw=]
cscli decisions list = /usr/local/bin/cscli_decisions_list.sh time_limit = 5
ban = /usr/local/bin/cscli_ban_ip.sh time_limit = 5
```

---

### 6.3. Usage: Triggering Remote Ban & Receiving Live Proof

From your admin workstation, dispatch the ban command to the OPNsense node:

```bash
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 day' '+%Y-%m-%d %H:%M:%S')" "ban 85.121.126.176" "opnsense.pub"
```

The listener on your workstation receives the return alert containing the updated CrowdSec table in real-time:

```bash
gorgona listen new
```

**Received Decrypted Response:**
```text
+---------+----------+-------------------+--------------------------------------+--------+---------+----------------------------------+--------+------------+----------+
|    ID   |  Source  |    Scope:Value    |                Reason                | Action | Country |                AS                | Events | expiration | Alert ID |
+---------+----------+-------------------+--------------------------------------+--------+---------+----------------------------------+--------+------------+----------+
| 4925356 | cscli    | Ip:85.121.126.176 | Banned via Gorgona P2P               | ban    |         |                                  | 1      | 23h59m59s  | 4060     |
| 4925355 | crowdsec | Ip:20.214.105.208 | crowdsecurity/http-probing           | ban    | KR      | 8075 MICROSOFT-CORP-MSN-AS-BLOCK | 11     | 3h35m1s    | 4059     |
| 4925354 | crowdsec | Ip:85.121.245.193 | crowdsecurity/http-probing           | ban    | RO      | 9009 M247 Europe SRL             | 11     | 3h3m6s     | 4058     |
| 4925352 | crowdsec | Ip:151.243.18.193 | firewallservices/pf-scan-multi_ports | ban    | US      | 207043 Dedik Services Limited    | 16     | 3h1m11s    | 4055     |
| 4895351 | crowdsec | Ip:34.62.82.165   | crowdsecurity/http-crawl-non_statics | ban    | BE      | 396982 GOOGLE-CLOUD-PLATFORM     | 45     | 33m38s     | 4051     |
+---------+----------+-------------------+--------------------------------------+--------+---------+----------------------------------+--------+------------+----------+
4 duplicated entries skipped
```
