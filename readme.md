![ ](gorgona.png)
---
#### Gorgona. End-to-End Encrypted Time-Locked Messaging with Remote Command Execution 
- [Introduction](#introduction)
- [Features](#features)
- [Advantages](#advantages)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Install Client](#install-client)
  - [Install Server](#install-server)
- [Usage](#usage)
  - [Flags](#flags)
  - [Generate Keys](#generate-keys)
  - [Send Message](#send-message)
  - [Listen for Messages](#listen-for-messages)
  - [Run Server](#run-server)
- [Configuration](#configuration)
  - [Client Configuration](#client-configuration)
  - [Server Configuration](#server-configuration)
- [Flowchart of Server Operation](#flowchart-of-server-operation)
- [Future Plans](#future-plans)
- [Testing](#testing) <a href="https://youtu.be/3JodTvfr88c"><img src="https://img.shields.io/badge/YouTube-Demo-red?logo=youtube" alt="YouTube Demo ▶" height="18" style="vertical-align:middle;"></a>
- [More examples](#more-examples)

---
##### Introduction

`gorgona` is a secure messaging system for sending encrypted messages that unlock at a specific time and expire after a set period. Using RSA for key exchange and AES-GCM for content encryption, `gorgona` ensures end-to-end privacy. The server stores only encrypted messages, unable to access their content, making it ideal for sensitive communications, scheduled notifications, or delayed message releases (e.g., time capsules or emergency data sharing, telemetry transport.).

The project includes a client (`gorgona`) for key generation, sending messages, and listening for alerts, and a server (`gorgonad`) for securely storing and delivering them.

##### Features

- **Time Capsule**: A decentralized crontab with 1ms UTC precision for time-locked message execution between unlock_at and expire_at.
- **End-to-End Encryption**: Messages are encrypted on the client and decrypted only by the recipient with their private key.
- **Optional Persistent Storage**: Enable disk-based storage for alerts (default: disabled, configurable via `use_disk_db`). When enabled, alerts are saved to `/var/lib/gorgona/alerts/` for persistence across restarts; otherwise, operate in memory-only mode for lightweight deployments.
- **Privacy-First**: The server handles only encrypted data, ensuring no access to message content.
- **Key Management**: Generates RSA key pairs named by the base64-encoded hash of the public key for secure sharing and local private key storage. The `hash` in `hash.pub` is used to specify the sender in the `listen` command; if omitted, messages for all `*.pub` keys in `/etc/gorgona/` are retrieved. To decrypt messages, the recipient must have the sender’s `hash.key` private key in `/etc/gorgona/`, which must be securely shared by the user.
- **Flexible Subscription Modes**: Listen in "live" (unlocked messages), "all" (non-expired messages, including locked), "lock" (locked messages only), "single" (specific recipient), or "last" (most recent message(s), optionally with count).
- **Command Execution Mode**: Use the `-e/--exec` flag with `listen` to execute received messages as system commands (requires specifying `pubkey_hash_b64` for security; messages from the specified key are treated as executable commands upon decryption).
- **When combined with the -d flag**: commands are executed in the background as detached daemons, making them immune to parent process termination (e.g., when running under systemd). This is especially useful for long-running processes like gpstart or custom services. All stdout/stderr from such commands is redirected to the path in gorgona_LOG_FILE, enabling centralized logging.
- **Sub-Second Time-Locked Execution**: In `lock/new` mode with `-e/--exec`, the client precisely executes commands at the exact `unlock_at` moment (±10ms), using a `select()`-based event loop. No busy-waiting - ideal for cron-like automation with cryptographic security.
- **Efficient Storage**: Uses a ring buffer, limiting alerts per recipient to a configurable number (default: 1000), automatically removing the oldest or expired messages.
- **Decentralized Design**: Users control keys, and the lightweight server supports self-hosting.
- **Fast and Lightweight**: Built with OpenSSL, requiring minimal dependencies.
- **Tamper-Proof**: GCM authentication tags and RSA-OAEP padding protect against tampering.
- **Interactive Server Status via Telnet**: Connect via `telnet <server> <port>` and use commands like `info`, `version`, or `?` to instantly view server version, uptime (e.g., `1d 21h 45m`), max clients, and message size limits - ideal for quick health checks without logs.

##### Advantages

- **Uncompromised Security**: Messages remain confidential even if the server is breached.
- **Versatile Use Cases**: Ideal for personal reminders, corporate alerts, whistleblower tools, or automated data releases.
- **Scalable Architecture**: Simple TCP server handles multiple clients (default: 100, configurable), with potential for load balancing.
- **No Third-Party Reliance**: Operates locally or via direct client-server communication.
- **Creative Applications**: Build time capsules, gamified messaging, or secure delayed backups.
- **Flexible Storage Options**: Run in memory-only mode for high-speed, ephemeral operations or enable disk persistence for durability without losing alerts on server restarts.

##### Quick Start

```bash
git clone --depth 1 https://github.com/psqlmaster/gorgona.git && \
cd gorgona && \
make clean && make && \
sudo mkdir -p /etc/gorgona && \
printf "[server]\nip = 46.138.247.148\nport = 7777\n" | sudo tee /etc/gorgona/gorgona.conf >/dev/null && \
sudo mv RWTPQzuhzBw=.pub RWTPQzuhzBw=.key /etc/gorgona/ && \
sudo cp ./gorgona /usr/bin && \
gorgona listen last 4 RWTPQzuhzBw=
```

##### Installation

Clone the repository:

```bash
git clone https://github.com/psqlmaster/gorgona.git
cd gorgona
```

Install dependencies (OpenSSL required):

- On Debian/Ubuntu: `sudo apt install -y libssl-dev git gcc make`
- On Fedora: `sudo dnf install openssl-devel`
- On REDOS: `sudo yum install openssl11 openssl11-devel`
- On centos: `sudo yum install -y git gcc make pkgconfig check check-devel openssl-devel`
- On macOS: `brew install openssl`

> Note: Tested on Debian, Fedora, Centos and RED OS.

Build the project:

```bash
make clean && make
```

Builds `gorgona` (client) and `gorgonad` (server). Clean: `make clean`. Rebuild: `make rebuild`.

### [Install Client](https://github.com/psqlmaster/gorgona/releases)

```bash
sudo dpkg -i ./gorgona_2.5.8_amd64.deb
```

### [Install Server](https://github.com/psqlmaster/gorgona/releases)

```bash
sudo dpkg -i ./gorgonad_2.5.8_amd64.deb
```

##### Usage

```bash
gorgona [-v|--verbose] [-e|--exec] [-d|--daemon-exec] [-h|--help] [-V|--version] <command> [arguments]
```

##### Flags

- `-v, --verbose`: Enables verbose output for debugging.
- `-e, --exec`: For 'listen' command: execute messages as system commands (requires `pubkey_hash_b64`).
- `-d, --daemon-exec`: Used with `-e/--exec` for 'listen' command: executes messages as **background daemons** (via `fork()` + `setsid()`).  
      Output from executed commands is written to the file specified by the environment variable `gorgona_LOG_FILE` (e.g., `gorgona_LOG_FILE=/var/log/gorgona.log gorgona -ed listen new ...`).  
      If `gorgona_LOG_FILE` is not set, command output is discarded (`/dev/null`).
  - If the `[exec_commands]` section in `/etc/gorgona/gorgona.conf` is empty, all decrypted messages are executed.
  - If `[exec_commands]` contains entries (e.g., `greengage start = /path/to/script.sh`), only messages matching a key are executed by running the corresponding script.
- `-h, --help`: Displays help message.
- `-V, --version`: Current version.

> Note: Flags `-v` and `-e` can be combined (e.g., `-ve`) for verbose output during command execution.

##### Generate Keys

```bash
sudo gorgona genkeys
```

Generates an RSA key pair in `/etc/gorgona/`, creating `hash.pub` (public key) and `hash.key` (private key), where `hash` is the base64-encoded hash of the public key.

The `hash` in name file `hash.pub` is used to specify the sender in the `listen` command; if omitted, messages for all `*.pub` keys in `/etc/gorgona/` are retrieved.

To decrypt messages, the recipient must have the sender’s `hash.key` private key in `/etc/gorgona/`, which must be securely shared by the user.

**Key Permissions**: Private keys (`*.key`) should be readable only by the owner (`chmod 600`). Public keys (`*.pub`) can be world-readable (`chmod 644`). Check permissions with:

```bash
ls -la /etc/gorgona
```

### Send Message 
- (datetime UTC) or date -u '+%Y-%m-%d %H:%M:%S'

```bash
# gorgona send <data unlock message> <data expired> "Your message" "recipient.pub"
gorgona send "YYYY-MM-DD HH:MM:SS" "YYYY-MM-DD HH:MM:SS" "Your message" "recipient.pub"
```

Use `-` for `<message>` to read from stdin. 
The public key file is the filename in `/etc/gorgona/`, e.g., `RWTPQzuhzBw=.pub`.

**Examples**:

```bash
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "hello world" "RWTPQzuhzBw=.pub"
gorgona send "$(date -u -d '+30 seconds' '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "Message in the future for you my dear friend RWTPQzuhzBw=" "RWTPQzuhzBw=.pub"
cat message.txt | gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" - "RWTPQzuhzBw=.pub"
```

### Listen for Messages

```bash
gorgona listen <mode> [<count>] [pubkey_hash_b64]
```

**Modes**:
- `live`:   Only active messages (`unlock_at <= now`).
- `all`:    All non-expired messages, including locked.
- `lock`:   Only locked messages (`unlock_at > now`).
- `single`: Only active messages for the given `pubkey_hash_b64`.
- `last`:   the most recent [<count>] message(s), (count defaults to 1), optionally filtered by pubkey_hash_b64
- `new`:    Only new messages received after connection, optionally filtered by `pubkey_hash_b64`.

If `pubkey_hash_b64` is provided, filters by it (mandatory for `single` and `last`).

**Examples**:

```bash
# Examples: Listen modes
gorgona listen single RWTPQzuhzBw=     # Gets the message from single key
gorgona listen last RWTPQzuhzBw=       # Gets the last 1 message
gorgona listen last 3 RWTPQzuhzBw=     # Gets the last 3 messages
gorgona listen new RWTPQzuhzBw=        # Receives only new messages from the moment of connection
gorgona listen new                     # Receives only new messages for all keys since connection
# Time-Locked Command Execution (cron-like)
# Start listener in lock mode - it will execute the command exactly at unlock time
gorgona -e listen lock RWTPQzuhzBw=
# In another terminal: send a command that unlocks in 10 seconds
gorgona send "$(date -u -d '+10 seconds' '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "{ date; uptime; }" "RWTPQzuhzBw=.pub"
# After ~10s the listener with -e executes the decrypted command at unlock_at
# Same lock mode but without execution: decrypt & display at unlock time
# Start listener (no -e) - message is queued and shown when unlocked
gorgona listen lock RWTPQzuhzBw=
# Send the same message (unlocks in 10s) from another terminal
gorgona send "$(date -u -d '+10 seconds' '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "test message" "RWTPQzuhzBw=.pub"
# After ~10s the listener without -e prints: "Unlocked pending message ID=..." and the decrypted text
gorgona -ed listen new RWTPQzuhzBw=     # Listens for new messages and executes them as background daemons
gorgona_LOG_FILE=/var/log/gorgona.log gorgona -edv listen lock RWTPQzuhzBw=  # Executes locked commands in background with logging command output to a central log
```

- You can check server status from any device using standard telnet/nc
```bash 
echo "info" | nc 46.138.247.148 7777
# Output:
# Gorgona Server 2.7.2
# Uptime: 12d 4h 20m
# Max message size: 5242880 bytes
# Max clients: 100
```

##### Run Server

```bash
gorgonad [-v|--verbose] [-h|--help] [-V|--version]
```
- The server reads settings from `/etc/gorgona/gorgonad.conf` or uses defaults (port = 5555, max alerts = 1000, max clients = 100, log_level = "info", use_disk_db = false).
- Use `-h` or `--help` for configuration help.  
- Use `-v` for verbose mode, example:

```bash
strace -e network gorgona -v listen new RWTPQzuhzBw=
```

The server reads settings from `/etc/gorgona/gorgonad.conf` or uses defaults (port: 5555, max alerts: 1024, max clients: 100).

##### Configuration

##### Client Configuration (Variant A)

The file `/etc/gorgona/gorgona.conf` contains server settings and optional execution mappings:

```ini
[server]
ip = 46.138.247.148 
port = 7777

[exec_commands]
<key> = <script_path>
```

**Example**:

```ini
[exec_commands]
app start = /home/su/repository/c/gorgona/test/script.sh
```

##### Recommended (Variant B) - per-key sections
---

Prefer using named subsections to group commands by required public-key hash. This is explicit, easy to read, and less error-prone.

```ini
[exec_commands:RWTPQzuhzBw=]
weather = /usr/local/bin/gorgona_weather_sender.sh
greengage start = /root/scripts/greengage_start.sh

[exec_commands:IcUimbs6LZY=]
la = /root/scripts/la.sh
vm list running = /root/scripts/qm_list_running.sh

[exec_commands]   ; global commands, available for all keys
sysadmin = /usr/local/bin/gorgona_sysadmin.sh
```

Notes:
- A header `[exec_commands:KEY]` binds all key/value lines inside to `required_key=KEY`. Only messages decrypted with the matching private key (i.e., whose `pubkey_hash_b64` equals `KEY`) may execute those commands when `-e/--exec` is used.
- `[exec_commands]` (without suffix) is the global section — commands there are available to messages from any key.
- This format is both human-editable and easy to generate with configuration management tools (Ansible, Chef, etc.).

Backward compatibility:
- The parser also accepts the older minimal form `key = <value>` inside `[exec_commands]` (legacy), but using per-key sections is recommended.

##### Wrapper Script Support for Complex Commands
- For complex shell commands with pipes, variables, or dynamic content, use wrapper scripts instead of inline commands. 
- This avoids shell escaping issues and provides better maintainability. Arguments from gorgona messages are passed to the script as $1, $2, $3...

**Example: Remote Service & Log Manager**
- /usr/local/bin/gorgona_sysadmin.sh
```bash
#!/bin/bash

# Arguments: $1=action, $2=service, $3=parameter (optional)
# Usage examples:
#   sysadmin restart nginx
#   sysadmin logs postgres 100
#   sysadmin status sshd
#   sysadmin kill zombie 5

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ACTION="${1:-help}"
SERVICE="${2:-}"
PARAM="${3:-}"

TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M:%S')
PUBKEY="RWTPQzuhzBw=.pub"

case "$ACTION" in
    restart)
        RESULT=$(systemctl restart "$SERVICE" 2>&1 && echo "✓ $SERVICE restarted" || echo "✗ Failed to restart $SERVICE")
        ;;
    status)
        RESULT=$(systemctl status "$SERVICE" --no-pager 2>&1 | head -10)
        ;;
    logs)
        LINES="${PARAM:-50}"
        RESULT=$(journalctl -u "$SERVICE" --no-pager -n "$LINES" 2>&1)
        ;;
    kill)
        PATTERN="${PARAM:-$SERVICE}"
        RESULT=$(pkill -9 -f "$PATTERN" 2>&1 && echo "✓ Processes killed" || echo "✗ No processes found")
        ;;
    disk)
        # ИСПРАВЛЕНО: PATH -> CHECK_PATH (не перезаписывать системную переменную!)
        CHECK_PATH="${SERVICE:-/}"
        RESULT=$(du -sh "$CHECK_PATH" 2>&1 && df -h "$CHECK_PATH" 2>&1 | tail -1)
        ;;
    help|*)
        RESULT="Available: restart|status|logs|kill|disk <service> [param]"
        ;;
esac

echo "[$TIMESTAMP] $ACTION $SERVICE $PARAM
$RESULT" | /usr/bin/gorgona send "$TIMESTAMP" "$(date -u -d '+1 day' '+%Y-%m-%d %H:%M:%S')" - "$PUBKEY"
```
**Make it executable:**
```bash
chmod +x /usr/local/bin/gorgona_sysadmin.sh
```
**Configure exec_commands**
- Edit /etc/gorgona/gorgona.conf:
```ini
[server]
ip = 46.138.247.148
port = 7777

[exec_commands]
sysadmin = /usr/local/bin/gorgona_sysadmin.sh
```
**Usage Examples**
```bash
# Terminal 1: Start listener to execute commands at the exact 'unlock' moment
gorgona -e listen lock RWTPQzuhzBw=

# Terminal 2: Send a command to unlock exactly in 60 seconds
gorgona send "$(date -u -d '+60 seconds' '+%Y-%m-%d %H:%M:%S')" \
             "$(date -u -d '+1 day' '+%Y-%m-%d %H:%M:%S')" \
             "systemctl restart nginx" "RWTPQzuhzBw=.pub"
# example output:
# Decrypted message:
# [2026-03-01 14:49:48] restart nginx 
# ✓ nginx restarted

# Get last 100 lines of postgres logs
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 hour' '+%Y-%m-%d %H:%M:%S')" \
"sysadmin logs nginx 3" "RWTPQzuhzBw=.pub" && gorgona listen new
# example output:
# Decrypted message:
# [2026-03-01 14:49:21] logs nginx 3
# Feb 27 16:34:09 hostname nginx[1738727]: 2026/02/27 16:34:09 [warn] 1738727#1738727: conflicting server name "hostname.org" on 0.0.0.0:443, ignored
# Feb 27 16:34:09 hostname nginx[1738735]: 2026/02/27 16:34:09 [warn] 1738735#1738735: conflicting server name "hostname.org" on 0.0.0.0:80, ignored
# Feb 27 16:34:09 hostname nginx[1738735]: 2026/02/27 16:34:09 [warn] 1738735#1738735: conflicting server name "hostname.org" on 0.0.0.0:443, ignored

# Check sshd service status
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 hour' '+%Y-%m-%d %H:%M:%S')" \
"sysadmin status sshd" "RWTPQzuhzBw=.pub" && gorgona listen new
# example output:
# Decrypted message:
# sysadmin status sshd
# Received message: Pubkey_Hash=RWTPQzuhzBw=
# ID: 150268099387392
# Metadata (local): Create=2026-03-01 17:42:27, Unlock=2026-03-01 17:42:27, Expire=2026-03-02 17:42:27
# Decrypted message:
# [2026-03-01 14:42:27] status sshd 
# ● ssh.service - OpenBSD Secure Shell server
#      Loaded: loaded (/lib/systemd/system/ssh.service; enabled; preset: enabled)
#      Active: active (running) since Fri 2026-02-27 16:34:11 MSK; 2 days ago
#        Docs: man:sshd(8)
#              man:sshd_config(5)
#     Process: 1738962 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)
#    Main PID: 1738963 (sshd)
#       Tasks: 1 (limit: 153344)
#      Memory: 3.3M
#         CPU: 91ms

# Kill all zombie processes
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 hour' '+%Y-%m-%d %H:%M:%S')" \
"sysadmin kill zombie" "RWTPQzuhzBw=.pub" && gorgona listen new

# Check disk usage of /var/log
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 hour' '+%Y-%m-%d %H:%M:%S')" \
"sysadmin disk /var/log" "RWTPQzuhzBw=.pub" && gorgona listen new
# example output:
# Decrypted message:
# [2026-03-01 14:36:04] disk /var/log 
# 2.1G	/var/log
# /dev/mapper/pve-root   94G   63G   27G  71% /

# Listen and execute automatically
gorgona -ed listen new RWTPQzuhzBw=
```

### Server Configuration

Edit `/etc/gorgona/gorgonad.conf`:

```ini
[server]
port = 7777                      # Listen port (default: 5555)
max_alerts = 10000               # Max alerts stored per recipient key
max_clients = 100                # Max simultaneous TCP connections
max_message_size = 5             # Max message size in MB (default: 5)
use_disk_db = false              # Enable persistent storage in /var/lib/gorgona/alerts/
vacuum_threshold_percent = 25    # Auto-cleanup threshold for deleted/expired alerts

# Logging levels:
# error: Only critical errors.
# info : Connections, disconnections, and status changes (Default).
# debug: Full trace including raw command payloads and message metadata.
log_level = info                 
max_log_size = 10                # Log rotation limit in MB
```

> **Pro Tip: Debugging**
> Running `gorgonad -v` (verbose) will print **all** levels (including DEBUG) to your terminal in real-time, regardless of the `log_level` set in the config file. This is ideal for troubleshooting without bloating your `gorgonad.log`.

---

### Flowchart of Server Operation

The server uses a high-performance `select()`-based multiplexing loop to handle binary and text protocols simultaneously.

```mermaid
graph TD
    A[Start Server] --> B{Incoming Event}
    B -->|New Connection| C[Accept & Non-blocking setup]
    B -->|Data Received| D{Sniff Protocol}
    D -->|First Byte < 32| E[Binary Mode: Parse Length + Payload]
    D -->|First Byte >= 32| F[Text Mode: Interactive Commands / Telnet]
    E --> G[Command Dispatcher]
    F --> G
    G --> H[Process: SEND / LISTEN / SUBSCRIBE]
    H --> I[Queue Outbound Data]
    B -->|Socket Writable| J[Process Send Queue]
    J --> K[Rotate Logs & Cleanup Expired]
```

<details>
<summary><b>Click to view detailed internal logic (Packet parsing, State machine, DB Sync)</b></summary>

```ini
[Server Start]
   |
   v
[Initialization]
   - Read configuration (/etc/gorgona/gorgonad.conf)
   - Initialize Global Data: client_sockets[MAX_CLIENTS], subscribers[MAX_CLIENTS]
   - Setup Logging: Open gorgonad.log (Level: error, info, or debug)
   - If use_disk_db == true:
   |  - Load Recipients from /var/lib/gorgona/alerts/
   |  - mmap() existing .alerts files into memory
   |  - Scan files for active/corrupted records -> Set used_size & count
   |
   v
[Socket Creation]
   - socket(), setsockopt(SO_REUSEADDR), bind(), listen()
   - Set server_fd to O_NONBLOCK
   - Register Signal Handlers (SIGINT/SIGTERM for graceful shutdown, SIGPIPE ignore)
   |
   v
[Main Loop (run_server)]
   |
   |--[1] Prepare select() FD Sets:
   |      - Add server_fd to readfds
   |      - For each active client:
   |         - Add to readfds (if close_after_send is false)
   |         - Add to writefds (if has_pending_data is true: out_head != NULL)
   |
   |--[2] select(max_sd + 1, &readfds, &writefds, NULL, NULL)
   |
   |--[3] Handle NEW CONNECTION (FD_ISSET server_fd):
   |      - accept() -> check max_clients limit
   |      - If full: Send error -> close()
   |      - If OK: fcntl(O_NONBLOCK) -> Initialize Subscriber struct
   |         - Set read_state = READ_LEN, in_pos = 0, close_after_send = false
   |
   |--[4] Handle WRITABLE Client (FD_ISSET in writefds):
   |      - Call process_out(sub_index, sd):
   |         - Loop through OutBuffer queue -> send() payload chunks
   |         - If sent < len: Update pos -> Break (wait for next select)
   |         - If sent == len: Free buffer -> Move to next OutBuffer
   |         - If queue empty AND close_after_send == true:
   |            - Log "Task completed" -> close(sd) -> Reset Subscriber struct
   |
   |--[5] Handle READABLE Client (FD_ISSET in readfds):
   |      |
   |      |----> [State: READ_LEN (Protocol Sniffer)]
   |      |         - Read 1 byte into in_buffer
   |      |         - If byte < 32 AND not (\n, \r, \t): BINARY PROTOCOL
   |      |            - Collect 4 bytes -> ntohl() -> expected_msg_len
   |      |            - Check max_message_size -> Allocate in_buffer -> read_state = READ_MSG
   |      |         - Else: TEXT PROTOCOL (Interactive/Telnet)
   |      |            - Buffer bytes until '\n' -> trim_string()
   |      |            - If "info"/"version"/"?":
   |      |               - Format text response -> enqueue_text_only()
   |      |               - Set close_after_send = true (Graceful exit)
   |      |            - Else: log_event("WARN", "Unknown text command")
   |      |
   |      |----> [State: READ_MSG (Data Collection)]
   |      |         - Read up to expected_msg_len into allocated in_buffer
   |      |         - If complete: 
   |      |            - handle_command(sub_index, in_buffer) -> See [Dispatcher]
   |      |            - Free in_buffer -> Reset in_pos -> read_state = READ_LEN
   |
   v
[Command Dispatcher (handle_command)]
   |
   |----> [SEND|...]
   |         - Parse fields: hash, unlock_at, expire_at, payload, key, iv, tag
   |         - add_alert():
   |            - find_recipient() -> clean_expired_alerts()
   |            - If count >= max_alerts: remove_oldest_alert() (Ring Buffer)
   |            - base64_decode() content -> Save to Recipient.alerts
   |            - If use_disk_db: alert_db_save_alert() (Write to mmap, msync)
   |         - notify_subscribers():
   |            - Loop all clients -> Check mode/hash match
   |            - If match: format ALERT|... message -> enqueue_message()
   |
   |----> [LISTEN|... / SUBSCRIBE ]
   |         - Parse: mode (LIVE, ALL, LOCK, SINGLE, LAST, NEW), hash, count
   |         - Update Subscriber mode/pubkey_hash
   |         - send_current_alerts():
   |            - Sort alerts by ID (descending for LAST/SINGLE)
   |            - Filter by unlock_at/expire_at/mode
   |            - For each match: base64_encode() -> enqueue_message()
   |         - If mode == LAST: Set close_after_send = true
   |
   v
[Background Maintenance]
   - Log Rotation: If size > max_log_size -> rename gorgonad.log to .log.1
   - DB Vacuum: If use_disk_db AND waste_count > vacuum_threshold_percent:
   |  - alert_db_sync(): Compact .alerts file (remove inactive) -> remap mmap
   - Logging: log_event(level, ...)
      - If verbose (-v): Always print to stdout
      - If log_level (config) matches: Write to gorgonad.log
```
</details>

---

##### Future Plans

`gorgona` works efficiently with a single server. Future plans include server mirroring (replication) without external services (Redis, PostgreSQL) for speed, decentralization, and reliability. Possible approaches: gossip protocol for peer-to-peer synchronization or lightweight consensus (e.g., adapted Raft). Also considering blockchain-inspired ledgers (without mining) or CRDT for seamless sync. Suggestions welcome!

##### Testing

[![Demo Teaser](https://img.youtube.com/vi/3JodTvfr88c/maxresdefault.jpg)](https://youtu.be/3JodTvfr88c)

Watch the quick 30‑minute demo on YouTube: https://youtu.be/3JodTvfr88c
```bash
# To run the test suite, use the following command:
make clean && make test
```

##### More examples
```bash
# send
lsblk | gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" - "RWTPQzuhzBw=.pub"
# Server response: Alert added successfully

# get
gorgona listen last RWTPQzuhzBw=
# Received message: Pubkey_Hash=RWTPQzuhzBw=
# Metadata: Create=2025-10-08 08:39:52, Unlock=2025-09-28 18:44:00, Expire=2025-12-30 09:00:00
# Decrypted message: [output of lsblk]

# send command message
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "echo \$(date)" "RWTPQzuhzBw=.pub"

# listen execute command message
gorgona -e listen new RWTPQzuhzBw=
# Server response: Subscribed to new for the specified key
# Received message: ...
# Executing command: echo $(date)
# Sat Oct 11 10:32:49 PM MSK 2025
# Command return code: 0
```

 >**Hack for the most patient** - if you want not only to run a command on a remote host but also to receive its output, do it like this:

 ```bash
 gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "iostat -d | \
 gorgona send \"2025-09-28 21:44:00\" \"2030-12-30 12:00:00\" - \"RWTPQzuhzBw=.pub\"" "IcUimbs6LZY=.pub"
 ```

- If we listen on that channel:
 ```bash
 gorgona listen new RWTPQzuhzBw=
 gorgona listen last RWTPQzuhzBw=
 ```

 - we immediately get a reply with the output of `iostat`.
 **Added service for listen messages in mode `--exec`**:
 ```bash
 sudo tee /tmp/mkdir.sh  /dev/null << 'EOF'
 mkdir -p /tmp/test/test1/test2/test3 && cd /tmp/test/test1/test2/test3 && pwd | \
 gorgona send "2025-10-05 18:42:00" "2030-10-09 09:00:00" - "RWTPQzuhzBw=.pub"
 EOF
 
 chmod +x /tmp/mkdir.sh
 
 sudo tee /etc/gorgona/gorgona.conf  /dev/null << 'EOF'
 [server]
 ip = 46.138.247.148 
 port = 7777
 [exec_commands]
 mkdir testdir = /tmp/mkdir.sh
 EOF
 
 sudo tee /etc/systemd/system/gorgona.service  /dev/null << 'EOF'
 [Unit]
 Description=gorgona Message Listener
 After=network-online.target
 Wants=network-online.target
 
 [Service]
 Type=simple
 ExecStart=/usr/bin/gorgona -ed listen new RWTPQzuhzBw=  ##### -d process is daemon #####
 Restart=always
 RestartSec=5
 StartLimitBurst=10
 StartLimitIntervalSec=300
 User=root
 StandardOutput=journal
 StandardError=append:/var/log/gorgona_service.log
 KillMode=mixed
 TimeoutStopSec=30
 Environment=gorgona_LOG_FILE=/var/log/gorgona_service.log
 
 [Install]
 WantedBy=multi-user.target
 EOF
 
 sudo chmod 644 /etc/systemd/system/gorgona.service && \
 sudo systemctl daemon-reload && \
 sudo systemctl enable gorgona && \
 sudo systemctl start gorgona

sudo touch /var/log/gorgona_service.log
sudo chown user:user /var/log/gorgona_service.log
sudo chmod 644 /var/log/gorgona_service.log
 ```

```bash
# in new terminal, only mkdir
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "mkdir testdir" "RWTPQzuhzBw=.pub"

# mkdir & output message
gorgona listen new RWTPQzuhzBw= & pid=$!; gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "mkdir testdir" "RWTPQzuhzBw=.pub"; sleep 2; kill $pid
```
- Time-Locked Command Execution (Cron-like)
```sh
# Start listener in lock mode - it will execute the command exactly at unlock time (v - verbose mode)
gorgona -ev listen lock RWTPQzuhzBw=
# In another terminal Send a command that unlocks alert in 10 seconds
gorgona send "$(date -u -d '+10 seconds' '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "{ date; uptime; }" "RWTPQzuhzBw=.pub"
# Check and compare the time after 10 seconds. 
```
- Server Status via Telnet
```sh
telnet 46.138.247.148 7777
```
    Trying 46.138.247.148...
    Connected to 46.138.247.148.
    Escape character is '^]'.
    info
    Gorgona Alert Server 2.4.1
    Uptime: 1d 21h 45m
    Max message size: 5242880 bytes
    Max clients: 100
    https://github.com/psqlmaster/gorgona

- example starting service
```sh
# vim /etc/systemd/system/greenplum.service
[Unit] 
Description=Greenplum Database Cluster 
After=network.target 
Wants=network-online.target 
 
[Service] 
Type=forking 
User=gpadmin 
Group=gpadmin 
Environment=GPHOME=/usr/lib/gpdb 
Environment=MASTER_DATA_DIRECTORY=/data1/master/gpseg-1 
Environment=PATH=/usr/lib/gpdb/bin:/usr/local/bin:/usr/bin:/bin 
Environment=LD_LIBRARY_PATH=/usr/lib/gpdb/lib 
Environment=LC_ALL=en_US.UTF-8 
ExecStart=/usr/lib/gpdb/bin/gpstart -a 
ExecStop=/usr/lib/gpdb/bin/gpstop -aM fast 
PIDFile=/data1/master/gpseg-1/postmaster.pid 
TimeoutSec=300 
 
[Install] 
WantedBy=multi-user.target
```
```sh
# vim /etc/gorgona/gorgona.conf
[exec_commands]
start greenplum = /bin/systemctl start greenplum
stop greenplum  = /bin/systemctl stop greenplum
```
