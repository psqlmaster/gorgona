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
- [Testing](#testing)

---

##### Introduction

`gorgona` is a secure messaging system for sending encrypted messages that unlock at a specific time and expire after a set period. Using RSA for key exchange and AES-GCM for content encryption, `gorgona` ensures end-to-end privacy. The server stores only encrypted messages, unable to access their content, making it ideal for sensitive communications, scheduled notifications, or delayed message releases (e.g., time capsules or emergency data sharing).

The project includes a client (`gorgona`) for key generation, sending messages, and listening for alerts, and a server (`gorgonad`) for securely storing and delivering them.

##### Features

- **End-to-End Encryption**: Messages are encrypted on the client and decrypted only by the recipient with their private key.
- **Time-Locked Delivery**: Messages unlock at a specified `unlock_at` time and expire at `expire_at`.
- **Privacy-First**: The server handles only encrypted data, ensuring no access to message content.
- **Key Management**: Generates RSA key pairs named by the base64-encoded hash of the public key for secure sharing and local private key storage. The `hash` in `hash.pub` is used to specify the sender in the `listen` command; if omitted, messages for all `*.pub` keys in `/etc/gorgona/` are retrieved. To decrypt messages, the recipient must have the sender’s `hash.key` private key in `/etc/gorgona/`, which must be securely shared by the user.
- **Flexible Subscription Modes**: Listen in "live" (unlocked messages), "all" (non-expired messages, including locked), "lock" (locked messages only), "single" (specific recipient), or "last" (most recent message(s), optionally with count).
- **Command Execution Mode**: Use the `-e/--exec` flag with `listen` to execute received messages as system commands (requires specifying `pubkey_hash_b64` for security; messages from the specified key are treated as executable commands upon decryption).
- **Efficient Storage**: Uses a ring buffer, limiting alerts per recipient to a configurable number (default: 1000), automatically removing the oldest or expired messages.
- **Decentralized Design**: Users control keys, and the lightweight server supports self-hosting.
- **Fast and Lightweight**: Built with OpenSSL, requiring minimal dependencies.
- **Tamper-Proof**: GCM authentication tags and RSA-OAEP padding protect against tampering.

##### Advantages

- **Uncompromised Security**: Messages remain confidential even if the server is breached.
- **Versatile Use Cases**: Ideal for personal reminders, corporate alerts, whistleblower tools, or automated data releases.
- **Scalable Architecture**: Simple TCP server handles multiple clients (default: 100, configurable), with potential for load balancing.
- **No Third-Party Reliance**: Operates locally or via direct client-server communication.
- **Creative Applications**: Build time capsules, gamified messaging, or secure delayed backups.

##### Quick Start

```bash
git clone https://github.com/psqlmaster/gorgona.git && \
cd gorgona && \
make clean && make && \
sudo mkdir -p /etc/gorgona && \
printf "[server]\nip = 64.188.70.158\nport = 7777\n" | sudo tee /etc/gorgona/gorgona.conf >/dev/null && \
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

- On Debian/Ubuntu: `sudo apt install libssl-dev`
- On Fedora: `sudo dnf install openssl-devel`
- On REDOS: `sudo yum install openssl11 openssl11-devel`
- On macOS: `brew install openssl`

> Note: Tested on Debian, Fedora, and RED OS.

Build the project:

```bash
make clean && make
```

Builds `gorgona` (client) and `gorgonad` (server). Clean: `make clean`. Rebuild: `make rebuild`.

### Install Client

```bash
sudo dpkg -i ./gorgona_1.8.3_amd64.deb
```

### Install Server

```bash
sudo dpkg -i ./gorgonad_1.8.3_amd64.deb
```

##### Usage

```bash
gorgona [-v] [-e|--exec] [-h|--help] [-V|--version] <command> [arguments]
```

##### Flags

- `-v, --verbose`: Enables verbose output for debugging.
- `-e, --exec`: For 'listen' command: execute messages as system commands (requires `pubkey_hash_b64`).
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

```bash
gorgona send "YYYY-MM-DD HH:MM:SS" "YYYY-MM-DD HH:MM:SS" "Your message" "recipient.pub"
```

Use `-` for `<message>` to read from stdin.  
The public key file is the filename in `/etc/gorgona/`, e.g., `RWTPQzuhzBw=.pub`.

**Examples**:

```bash
gorgona send "2025-09-30 23:55:00" "2025-12-30 12:00:00" "Message in the future for you my dear friend RWTPQzuhzBw=" "RWTPQzuhzBw=.pub"
cat message.txt | gorgona send "2025-09-30 23:55:00" "2025-12-30 12:00:00" - "RWTPQzuhzBw=.pub"
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
gorgona listen single RWTPQzuhzBw=     # Gets the message from single key
gorgona listen last RWTPQzuhzBw=       # Gets the last 1 message
gorgona listen last 3 RWTPQzuhzBw=     # Gets the last 3 messages
gorgona listen new RWTPQzuhzBw=        # Receives only new messages from the moment of connection
gorgona listen new                     # Receives only new messages for all keys since connection
gorgona -e listen new RWTPQzuhzBw=     # Listens for new messages and executes them as system commands
```

##### Run Server

```bash
gorgonad [-v] [-h|--help]
```

Use `-h` or `--help` for configuration help.  
Use `-v` for verbose mode, example:

```bash
strace -e network gorgona -v listen new RWTPQzuhzBw=
```

The server reads settings from `/etc/gorgona/gorgonad.conf` or uses defaults (port: 5555, max alerts: 1024, max clients: 100).

##### Configuration

##### Client Configuration

The file `/etc/gorgona/gorgona.conf` contains server settings and optional execution mappings:

```ini
[server]
ip = 64.188.70.158
port = 7777

[exec_commands]
<key> = <script_path>
```

**Example**:

```ini
[exec_commands]
app start = /home/su/repository/c/gorgona/test/script.sh
```

### Server Configuration

Edit `/etc/gorgona/gorgonad.conf`:

```ini
[server]
port = 7777
MAX_ALERTS = 2000
MAX_CLIENTS = 100
max_message_size = 5242880
```

- `port`: TCP port (default: 5555).
- `MAX_ALERTS`: Max alerts per recipient (default: 1024).
- `MAX_CLIENTS`: Max simultaneous connections (default: 100).
- `max_message_size`: Max message size in bytes (default: 5242880, 5 MB).

If the file is missing, defaults are used.  
Logs are written to `gorgona.log` with rotation when exceeding 10 MB.

## Flowchart of Server Operation

```ini
[Server Start]
   |
   v
[Initialization]
   - Read configuration (/etc/gorgona/gorgonad.conf)
   - Initialize client_sockets and subscribers arrays
   - Allocate memory for recipients (INITIAL_RECIPIENT_CAPACITY)
   - Open log file (gorgonad.log)
   |
   v
[Socket Creation]
   - socket(), setsockopt(SO_REUSEADDR), bind(), listen()
   - Register signal handlers (SIGINT, SIGTERM)
   |
   v
[Main Loop (run_server)]
   |
   v
[select: Wait for Activity]
   |
   |----> [New Client (accept)]
   |         - Check max_clients limit
   |         - Add to client_sockets and subscribers
   |         - Log connection
   |
   |----> [Client Data]
            |
            v
         [Read Message Length]
            - Check for errors/disconnection
            - Verify max_message_size
            |
            v
         [Read Message]
            - Check for HTTP request (reject with 400)
            - Parse command (SEND, LISTEN, SUBSCRIBE)
            |
            |----> [SEND]
            |       - Parse: pubkey_hash, unlock_at, expire_at, text, key, iv, tag
            |       - add_alert:
            |          - Find/create Recipient
            |          - Clean expired alerts
            |          - Remove oldest alert if count >= max_alerts
            |          - Decode base64 and add Alert
            |       - Send response to client
            |       - notify_subscribers (for matching subscribers)
            |
            |----> [LISTEN]
            |       - Parse: pubkey_hash, mode (SINGLE/LAST), count
            |       - Set mode in subscribers
            |       - send_current_alerts:
            |          - SINGLE: alerts with unlock_at <= now
            |          - LAST: last count alerts (sorted by create_at)
            |       - Close connection (for LAST)
            |
            |----> [SUBSCRIBE]
                    - Parse: mode (LIVE/ALL/LOCK/LAST/NEW), pubkey_hash
                    - Set mode in subscribers
                    - send_current_alerts (except for MODE_NEW)
                    - Close connection (for LAST)
                    - Wait for new alerts (for LIVE/ALL/LOCK/NEW)

[Cleanup on Shutdown]
   - Free memory for recipients and alerts
   - Close sockets
   - Close log file
```

##### Future Plans

`gorgona` works efficiently with a single server. Future plans include server mirroring (replication) without external services (Redis, PostgreSQL) for speed, decentralization, and reliability. Possible approaches: gossip protocol for peer-to-peer synchronization or lightweight consensus (e.g., adapted Raft). Also considering blockchain-inspired ledgers (without mining) or CRDT for seamless sync. Suggestions welcome!

##### Testing

```bash
# To run the test suite, use the following command:
make clean && make test
```

**More examples**:

```bash
# send
lsblk | gorgona send "2025-09-28 21:44:00" "2025-12-30 12:00:00" - "RWTPQzuhzBw=.pub"
# Server response: Alert added successfully

# get
gorgona listen last RWTPQzuhzBw=
# Received message: Pubkey_Hash=RWTPQzuhzBw=
# Metadata: Create=2025-10-08 08:39:52, Unlock=2025-09-28 18:44:00, Expire=2025-12-30 09:00:00
# Decrypted message: [output of lsblk]

# send command message
gorgona send "2025-10-05 18:42:00" "2026-10-09 09:00:00" "echo \$(date)" "RWTPQzuhzBw=.pub"

# listen execute command message
gorgona -e listen new RWTPQzuhzBw=
# Server response: Subscribed to new for the specified key
# Received message: ...
# Executing command: echo $(date)
# Sat Oct 11 10:32:49 PM MSK 2025
# Command return code: 0
```

 **Hack for the most patient** — if you want not only to run a command on a remote host but also to receive its output, do it like this:

 ```bash
 gorgona send "2025-09-28 21:44:00" "2025-12-30 12:00:00" "iostat -d | \
 gorgona send \"2025-09-28 21:44:00\" \"2025-12-30 12:00:00\" - \"RWTPQzuhzBw=.pub\"" "IcUimbs6LZY=.pub"
 ```

 If we listen on that channel:

 ```bash
 gorgona listen new RWTPQzuhzBw=
 gorgona listen last RWTPQzuhzBw=
 ```

 we immediately get a reply with the output of `iostat`.

 **Added service for listen messages in mode `--exec`**:

 ```bash
 sudo tee /tmp/mkdir.sh  /dev/null << 'EOF'
 mkdir -p /tmp/test/test1/test2/test3 && cd /tmp/test/test1/test2/test3 && pwd | \
 gorgona send "2025-10-05 18:42:00" "2026-10-09 09:00:00" - "RWTPQzuhzBw=.pub"
 EOF
 
 chmod +x /tmp/mkdir.sh
 
 sudo tee /etc/gorgona/gorgona.conf  /dev/null << 'EOF'
 [server]
 ip = 64.188.70.158
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
 ExecStart=/usr/bin/gorgona -e listen new RWTPQzuhzBw=
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
 ```

```bash
# in new terminal, only mkdir
gorgona send "2025-10-05 18:42:00" "2026-10-09 09:00:00" "mkdir testdir" "RWTPQzuhzBw=.pub"

# mkdir & output message
gorgona listen new RWTPQzuhzBw= & pid=$!; gorgona send "2025-09-28 21:44:00" "2025-12-30 12:00:00" "mkdir testdir" "RWTPQzuhzBw=.pub"; sleep 2; kill $pid
```

