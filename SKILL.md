---
description: "CLI for decentralized P2P messaging and remote command execution (Gorgona v3.1.5). Contains exact command templates for sending, listening, file sync, and remote execution."
---

# Gorgona CLI

**Binary:** `gorgona`  
**Config:** `/etc/gorgona/gorgona.conf`  
**Keys Directory:** `/etc/gorgona/` *(The CLI automatically prepends this path. Do NOT include it in your arguments!)*

## 1. SENDING MESSAGES

Always use this exact template. Replace `<KEY>` (e.g., `RWTPQzuhzBw=`) and `<MESSAGE>`.  
**CRITICAL:** Pass ONLY the filename `<KEY>.pub`, without the absolute path!

```bash
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "<MESSAGE>" "<KEY>.pub"
```

Via pipe (read payload from stdin — use `-` instead of the message):

```bash
df -h | gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" - "<KEY>.pub"
```

## 2. LISTENING (requires raw `<KEY>`, WITHOUT `.pub`)

| User Request | Command |
|---|---|
| Last message from a key | `gorgona listen last 1 "<KEY>"` |
| Last N messages from a key | `gorgona listen last <N> "<KEY>"` |
| Subscribe to new messages from a key | `gorgona listen new "<KEY>"` |
| Subscribe to new messages from all keys | `gorgona listen new` |
| Active messages from a key | `gorgona listen single "<KEY>"` |
| All active messages | `gorgona listen live` |
| All non-expired messages (incl. locked) | `gorgona listen all` |
| Locked messages only | `gorgona listen lock` |

## 3. EXECUTION MODE (EXEC)

To make the agent execute received decrypted messages as shell commands, add the `-e` flag **before** the `listen` subcommand:

```bash
gorgona -e listen new "<KEY>"
```

Flag combinations:
- `-e` : Execute decrypted messages.
- `-d` : Detach execution (fork + setsid), requires `-e`.
- `-v` : Verbose/debug output.
- `-ve`, `-ved`, `-veV` : Combine freely.

## 4. FILES & REVOCATION

- Send a file: `gorgona send-file "<LOCAL_PATH>" "<KEY>.pub"`
- Send a file with renaming: `gorgona send-file --name "<remote/path>" "<LOCAL_PATH>" "<KEY>.pub"`
- Send a file with custom timelocks: `gorgona send-file "<unlock>" "<expire>" "<LOCAL_PATH>" "<KEY>.pub"`
- Revoke a message (dead-hand): `gorgona revoke <ALERT_ID> "<KEY>"`

## 5. KEY GENERATION

```bash
gorgona genkeys
```
Generates an RSA key pair in `/etc/gorgona/`.

## 6. CONFIGURATION

`/etc/gorgona/gorgona.conf`:

```ini
[server]
  ip            = 64.188.70.158
  port          = 7777
  sync_psk      = <shared secret>   # optional, enables layer-2 mesh
  data_dir      = /var/lib/gorgona
  conf_dir      = /etc/gorgona

[exec_commands]
  <key>         = <script_path>   time_limit = <sec>
  # example: app start = /usr/local/bin/app_start.sh  time_limit = 60

[exec_commands:<pubkey>]
  # override commands for a specific key

[sync]
  max_file_size = 10485760   # global limit, bytes (default 10 MiB)

[sync:<pubkey>]
  dir           = /etc/nginx/conf.d   # root directory for this key
  direction     = rw   # ro | wo | rw
  on_change     = nginx -s reload   # command to run after successful sync
  max_file_size = 5242880   # optional per-key limit
```

## 7. WORKING EXAMPLES

```bash
gorgona listen single RWTPQzuhzBw=
gorgona listen last RWTPQzuhzBw=
gorgona listen last 3 RWTPQzuhzBw=
gorgona listen new RWTPQzuhzBw=
gorgona -e listen new RWTPQzuhzBw=
gorgona -ve listen new RWTPQzuhzBw=
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "hello world" "RWTPQzuhzBw=.pub"
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "app start" "RWTPQzuhzBw=.pub"
df -h | gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" - "RWTPQzuhzBw=.pub"
gorgona send-file /etc/nginx/conf.d/site.conf RWTPQzuhzBw=.pub
gorgona send-file --name conf.d/new_name_site.conf /etc/nginx/conf.d/site.conf RWTPQzuhzBw=.pub
gorgona revoke 170119927746560 RWTPQzuhzBw=
```

## ⚠️ CRITICAL RULES FOR THE AGENT

1. **KEY PATHS:**  
   - For `send` and `send-file`, pass **ONLY THE FILENAME**: `"RWTPQzuhzBw=.pub"`.  
   - **DO NOT USE** absolute paths like `/etc/gorgona/RWTPQzuhzBw=.pub`! The CLI automatically prepends `conf_dir` (`/etc/gorgona/`) to your argument. If you pass an absolute path, it causes fatal duplication: `/etc/gorgona//etc/gorgona/...` and the command will fail with exit code 1.  
   - For `listen` and `revoke`, use **ONLY** the raw hash: `"RWTPQzuhzBw="` (without `.pub`).
2. **Date Format:** Do not try to compute dates manually. Just copy the exact bash substitution: `$(date -u '+%Y-%m-%d %H:%M:%S')` and `$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')`.
3. **Argument Order for `send`:** `<unlock> <expire> <message> <pubkey_file>` — strictly in this order.
4. **Flag Placement:** The `-e` flag goes **before** the subcommand: `gorgona -e listen ...`, NOT `gorgona listen -e ...`.
5. **No Reconnaissance:** Do not waste tokens on reconnaissance (`ls`, `cat`, `--help`). All paths, formats, and rules are explicitly defined in this document.
