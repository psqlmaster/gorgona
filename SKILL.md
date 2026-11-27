---
description: "CLI for decentralized P2P messaging and remote command execution (Gorgona v3.1.6). Contains exact command templates for sending, listening, file sync, and remote execution."
---

# Gorgona CLI

**Binary:** `gorgona`  
**Config:** `/etc/gorgona/gorgona.conf`  
**Keys Directory:** `/etc/gorgona/` *(a bare key name is resolved against this directory)*

## 0. KEY ARGUMENT FORMS (apply to every command)

Any command that takes a key accepts all of these forms, they are equivalent:

| Form | Example |
|---|---|
| Bare hash | `RWTPQzuhzBw=` |
| Public file name | `RWTPQzuhzBw=.pub` |
| Private file name | `RWTPQzuhzBw=.key` |
| Full path | `/etc/gorgona/RWTPQzuhzBw=.pub` |

The CLI resolves the argument to the real key file of the required type: `send` and
`send-file` always use the public key, `listen` and `revoke` the private one. An
argument marked with the wrong extension (for example `RWTPQzuhzBw=.key` on `send`)
is automatically resolved to the matching key of the right type.

## 1. SENDING MESSAGES

Always use this exact template. Replace `<KEY>` (e.g., `RWTPQzuhzBw=`) and `<MESSAGE>`.  
The key may be written in any form from section 0.

```bash
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "<MESSAGE>" "<KEY>.pub"
```

Via pipe (read payload from stdin — use `-` instead of the message):

```bash
df -h | gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" - "<KEY>.pub"
```

## 2. LISTENING (key in any form from section 0)

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

**Note:** section names `[exec_commands:<pubkey>]` and `[sync:<pubkey>]` must contain the bare hash `RWTPQzuhzBw=`, without extension or path. Only command line arguments accept every form.

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

# The same commands with the key written differently, all valid
gorgona listen last 1 "RWTPQzuhzBw=.key"
gorgona listen new "/etc/gorgona/RWTPQzuhzBw=.key"
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')" "hello world" "/etc/gorgona/RWTPQzuhzBw=.pub"
gorgona revoke 170119927746560 /etc/gorgona/RWTPQzuhzBw.key
```

## ⚠️ CRITICAL RULES FOR THE AGENT

1. **KEY ARGUMENTS:**  
   - Any form works everywhere: bare hash, `<KEY>.pub`, `<KEY>.key` or a full path like `/etc/gorgona/RWTPQzuhzBw=.pub`.  
   - A bare name is resolved against `conf_dir` (`/etc/gorgona/`), so both `RWTPQzuhzBw=` and an absolute path are correct.  
   - The CLI picks the file of the type the command needs: public for `send`/`send-file`, private for `listen`/`revoke`. Do not pre-check which extension the key has.  
2. **Date Format:** Do not try to compute dates manually. Just copy the exact bash substitution: `$(date -u '+%Y-%m-%d %H:%M:%S')` and `$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')`.
3. **Argument Order for `send`:** `<unlock> <expire> <message> <pubkey>` — strictly in this order.
4. **Flag Placement:** The `-e` flag goes **before** the subcommand: `gorgona -e listen ...`, NOT `gorgona listen -e ...`.
5. **No Reconnaissance:** Do not waste tokens on reconnaissance (`ls`, `cat`, `--help`). All paths, formats, and rules are explicitly defined in this document.
