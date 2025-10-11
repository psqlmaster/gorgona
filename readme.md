# Gargona: Encrypted Time-Locked Messaging System

[Русская версия](#gargona-система-зашифрованного-алертинга-с-временной-блокировкой) | English Version

---
![ ](gargona.png)

## Gargona: Encrypted Time-Locked Messaging System

### Introduction

Gargona is a secure messaging system for sending encrypted messages that unlock at a specific time and expire after a set period. Using RSA for key exchange and AES-GCM for content encryption, Gargona ensures end-to-end privacy. The server stores only encrypted messages, unable to access their content, making it ideal for sensitive communications, scheduled notifications, or delayed message releases (e.g., time capsules or emergency data sharing).

The project includes a client (`gargona`) for key generation, sending messages, and listening for alerts, and a server (`gargonad`) for securely storing and delivering them.

### Features

- **End-to-End Encryption**: Messages are encrypted on the client and decrypted only by the recipient with their private key.
- **Time-Locked Delivery**: Messages unlock at a specified `unlock_at` time and expire at `expire_at`.
- **Privacy-First**: The server handles only encrypted data, ensuring no access to message content.
- **Key Management**: Generates RSA key pairs named by the base64-encoded hash of the public key for secure sharing and local private key storage. The `hash` in `hash.pub` is used to specify the sender in the `listen` command; if omitted, messages for all `*.pub` keys in `/etc/gargona/` are retrieved. To decrypt messages, the recipient must have the sender’s `hash.key` private key in `/etc/gargona/`, which must be securely shared by the user.
- **Flexible Subscription Modes**: Listen in "live" (unlocked messages), "all" (non-expired messages, including locked), "lock" (locked messages only), "single" (specific recipient), or "last" (most recent message(s), optionally with count).
- **Command Execution Mode**: Use the `-e/--exec` flag with `listen` to execute received messages as system commands (requires specifying `pubkey_hash_b64` for security; messages from the specified key are treated as executable commands upon decryption).
- **Efficient Storage**: Uses a ring buffer, limiting alerts per recipient to a configurable number (default: 1000), automatically removing the oldest or expired messages.
- **Decentralized Design**: Users control keys, and the lightweight server supports self-hosting.
- **Fast and Lightweight**: Built with OpenSSL, requiring minimal dependencies.
- **Tamper-Proof**: GCM authentication tags and RSA-OAEP padding protect against tampering.

**Advantages**:
- **Uncompromised Security**: Messages remain confidential even if the server is breached.
- **Versatile Use Cases**: Ideal for personal reminders, corporate alerts, whistleblower tools, or automated data releases.
- **Scalable Architecture**: Simple TCP server handles multiple clients (default: 100, configurable), with potential for load balancing.
- **No Third-Party Reliance**: Operates locally or via direct client-server communication.
- **Creative Applications**: Build time capsules, gamified messaging, or secure delayed backups.

## Quick Start
```bash
git clone https://github.com/psqlmaster/gargona.git && \
cd gargona && \
make clean && make && \
sudo mkdir -p /etc/gargona && \
printf "[server]\nip = 64.188.70.158\nport = 7777\n" | sudo tee /etc/gargona/gargona.conf >/dev/null && \
sudo mv RWTPQzuhzBw=.pub RWTPQzuhzBw=.key /etc/gargona/ && \
./gargona listen last 4 RWTPQzuhzBw=
```

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/psqlmaster/gargona.git
   cd gargona
   ```

2. Install dependencies (OpenSSL required):
   - On Debian/Ubuntu: `sudo apt install libssl-dev`
   - On Fedora: `sudo dnf install openssl-devel`
   - On REDOS: `sudo yum install openssl11 openssl11-devel`
   - On macOS: `brew install openssl`
   - **Note**: Tested on Debian, Fedora, and RED OS.

3. Build the project:
   ```bash
   make clean && make
   ```
   Builds `gargona` (client) and `gargonad` (server). Clean: `make clean`. Rebuild: `make rebuild`.

## Install Client
```bash
sudo dpkg -i ./gargona_1.7.0_amd64.deb
```

## Install Server
```bash
sudo dpkg -i ./gargonad_1.7.0_amd64.deb
```

### Usage
```sh
gargona [-v] [-e|--exec] [-h|--help] <command> [arguments]
```

#### Generate Keys
```bash
sudo gargona genkeys
```
- Generates an RSA key pair in `/etc/gargona/`, creating `hash.pub` (public key) and `hash.key` (private key), where `hash` is the base64-encoded hash of the public key.
- The `hash` in name file `hash.pub` is used to specify the sender in the `listen` command; if omitted, messages for all `*.pub` keys in `/etc/gargona/` are retrieved.
- To decrypt messages, the recipient must have the sender’s `hash.key` private key in `/etc/gargona/`, which must be securely shared by the user.
- **Key Permissions**: Private keys (`*.key`) should be readable only by the owner (`chmod 600`). Public keys (`*.pub`) can be world-readable (`chmod 644`). Check permissions with:
  ```bash
  ls -la /etc/gargona
  ```

#### Send Message
```bash
gargona send "YYYY-MM-DD HH:MM:SS" "YYYY-MM-DD HH:MM:SS" "Your message" "recipient.pub"
```
- Use `-` for `<message>` to read from stdin.
- The public key file is the filename in `/etc/gargona/`, e.g., `RWTPQzuhzBw=.pub`.
- Examples:
  ```bash
  gargona send "2025-09-30 23:55:00" "2025-12-30 12:00:00" "Message in the future for you my dear friend RWTPQzuhzBw=" "RWTPQzuhzBw=.pub"
  ```
  ```bash
  cat message.txt | gargona send "2025-09-30 23:55:00" "2025-12-30 12:00:00" - "RWTPQzuhzBw=.pub"
  ```

#### Listen for Messages
```bash
gargona listen  <mode> [<count>] [pubkey_hash_b64]
```
- Modes:
  - `live`:   Only active messages (`unlock_at <= now`).
  - `all`:    All non-expired messages, including locked.
  - `lock`:   Only locked messages (`unlock_at > now`).
  - `single`: Only active messages for the given `pubkey_hash_b64`.
  - `last`:   Most recent [<count>] message(s) for the given `pubkey_hash_b64` (count defaults to 1).
  - `new`:    Only new messages received after connection, optionally filtered by pubkey_hash_b64
- If `pubkey_hash_b64` is provided, filters by it (mandatory for `single` and `last`).
- Examples:
  ```bash
  gargona listen single RWTPQzuhzBw=  # Gets the message from single key
  gargona listen last RWTPQzuhzBw=    # Gets the last 1 message
  gargona listen last 3 RWTPQzuhzBw=  # Gets the last 3 messages
  gargona listen new RWTPQzuhzBw=     # Receives only new messages from the moment of connection  
  gargona listen new                  # Receives only new messages for all keys since connection 
  gargona -e listen new RWTPQzuhzBw=  # Listens for new messages and executes them as system commands
  ```

#### Run Server
```bash
gargonad [-v] [-h|--help]
```
- Use `-h` or `--help` for configuration help.
- Use `-v` for verbose mode
- The server reads settings from `/etc/gargona/gargonad.conf` or uses defaults (port: 5555, max alerts: 1024, max clients: 100).

### Configuration

#### Client Configuration
The file `/etc/gargona/gargona.conf` contains server settings:
```ini
[server]
ip = 64.188.70.158
port = 7777
```

#### Server Configuration
Edit `/etc/gargona/gargonad.conf`:
```ini
[server]
port = 7777
MAX_ALERTS = 2000
MAX_CLIENTS = 100
max_message_size = 5242880
```
- **port**: TCP port (default: 5555).
- **MAX_ALERTS**: Max alerts per recipient (default: 1024).
- **MAX_CLIENTS**: Max simultaneous connections (default: 100).
- **max_message_size**: Max message size in bytes (default: 5242880, 5 MB).
- If the file is missing, defaults are used.

Logs are written to `gargona.log` with rotation when exceeding 10 MB.

### Future Plans

Gargona works efficiently with a single server. Future plans include server mirroring (replication) without external services (Redis, PostgreSQL) for speed, decentralization, and reliability. Possible approaches: gossip protocol for peer-to-peer synchronization or lightweight consensus (e.g., adapted Raft). Also considering blockchain-inspired ledgers (without mining) or CRDT for seamless sync. Suggestions welcome!

[contributing.md](contributing.md) 

#### More examples:
```sh
# send
lsblk | gargona send "2025-09-28 21:44:00" "2025-12-30 12:00:00" - "RWTPQzuhzBw=.pub"
```
```
Server response: Alert added successfully
```
```sh
# get
gargona listen last RWTPQzuhzBw=
```
```
Received message: Pubkey_Hash=RWTPQzuhzBw=
Metadata: Create=2025-10-08 08:39:52, Unlock=2025-09-28 18:44:00, Expire=2025-12-30 09:00:00
Decrypted message: 
NAME        MAJ:MIN RM   SIZE RO TYPE  MOUNTPOINTS
sda           8:0    0 931.5G  0 disk  
└─sda1        8:1    0 931.5G  0 part  /mnt/share
sdb           8:16   0  14.6T  0 disk  
└─sdb1        8:17   0  14.6T  0 part  /mnt/megaraid
nvme1n1     259:0    0 476.9G  0 disk  
├─nvme1n1p1 259:5    0   512M  0 part  
├─nvme1n1p2 259:6    0 197.1G  0 part  
│ └─md0       9:0    0 196.9G  0 raid1 /
├─nvme1n1p3 259:7    0  27.8G  0 part  [SWAP]
└─nvme1n1p4 259:8    0 251.6G  0 part  /mnt/new_free
nvme0n1     259:1    0 476.9G  0 disk  
├─nvme0n1p1 259:2    0   197G  0 part  
│ └─md0       9:0    0 196.9G  0 raid1 /
├─nvme0n1p2 259:3    0   512M  0 part  /boot/efi
└─nvme0n1p3 259:4    0 279.4G  0 part  /mnt/backup
```
```sh
# send command message
gargona send "2025-10-05 18:42:00" "2026-10-09 09:00:00" "echo \$(date)" "RWTPQzuhzBw=.pub"
```
```
Server response: Alert added successfully
```
```sh
# listen execute command message
gargona -e listen new RWTPQzuhzBw=
```
```
Server response: Subscribed to new for the specified key
Received message: Pubkey_Hash=RWTPQzuhzBw=
Metadata: Create=2025-10-11 19:32:49, Unlock=2025-10-05 15:42:00, Expire=2026-10-09 06:00:00
Executing command: echo $(date)
Sat Oct 11 10:32:49 PM MSK 2025
Command return code: 0
```

## Gargona: система зашифрованного алертинга с временной блокировкой

### Введение

Gargona — безопасная система сообщений для отправки зашифрованных сообщений, которые разблокируются в указанное время и истекают после заданного периода. Используя RSA для обмена ключами и AES-GCM для шифрования содержимого, Gargona обеспечивает конфиденциальность от начала до конца. Сервер хранит только зашифрованные сообщения, не имея доступа к их содержимому, что идеально для конфиденциальных коммуникаций, запланированных уведомлений или отложенного раскрытия сообщений (например, временные капсулы или обмен данными в чрезвычайных ситуациях).

Проект включает клиент (`gargona`) для генерации ключей, отправки сообщений и прослушивания алертов, и сервер (`gargonad`) для их безопасного хранения и доставки.

### Возможности

- **Шифрование от конца до конца**: Сообщения шифруются на клиенте и расшифровываются только получателем с приватным ключом.
- **Временная блокировка доставки**: Сообщения разблокируются в указанное время `unlock_at` и истекают в `expire_at`.
- **Приоритет конфиденциальности**: Сервер работает только с зашифрованными данными, без доступа к содержимому.
- **Управление ключами**: Генерирует пары RSA-ключей, названные по хешу публичного ключа для безопасного обмена и локального хранения приватного ключа.
- **Гибкие режимы подписки**: Прослушивание в "live" (разблокированные сообщения), "all" (неистёкшие сообщения, включая заблокированные), "lock" (только заблокированные), "single" (для конкретного получателя) или "last" (самое недавнее сообщение(я), с опциональным счётом).
- **Режим выполнения команды**: Используйте `-e/--exec` флаг с `listen` чтобы выполнять полученные сообщения как системные команды (requires specifying `pubkey_hash_b64` for security; messages from the specified key are treated as executable commands upon decryption).
- **Эффективное хранение**: Кольцевой буфер ограничивает алерты на получателя (по умолчанию: 1000), автоматически удаляя старые или истёкшие.
- **Децентрализованный дизайн**: Пользователи контролируют ключи, сервер лёгкий и подходит для хостинга.
- **Быстрота и лёгкость**: Использует OpenSSL с минимальными зависимостями.
- **Защита от подделки**: Теги GCM и RSA-OAEP предотвращают вмешательство.

**Преимущества**:
- **Безопасность**: Сообщения конфиденциальны даже при компрометации сервера.
- **Универсальность**: Подходит для напоминаний, уведомлений, инструментов для информаторов или автоматической отправки данных.
- **Масштабируемость**: TCP-сервер поддерживает множество клиентов (по умолчанию: 100) и может быть расширен.
- **Без внешних сервисов**: Работает локально или через прямое взаимодействие клиент-сервер.
- **Креативные сценарии**: Временные капсулы, игровые сообщения или безопасные резервные копии.

## Быстрый старт
```bash
git clone https://github.com/psqlmaster/gargona.git && \
cd gargona && \
make clean && make && \
sudo mkdir -p /etc/gargona && \
printf "[server]\nip = 64.188.70.158\nport = 7777\n" | sudo tee /etc/gargona/gargona.conf >/dev/null && \
sudo mv RWTPQzuhzBw=.pub RWTPQzuhzBw=.key /etc/gargona/ && \
./gargona listen last 4 RWTPQzuhzBw=
```

### Установка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/psqlmaster/gargona.git
   cd gargona
   ```

2. Установите зависимости (требуется OpenSSL):
   - На Debian/Ubuntu: `sudo apt install libssl-dev`
   - На Fedora: `sudo dnf install openssl-devel`
   - На REDOS: `sudo yum install openssl11 openssl11-devel`
   - На macOS: `brew install openssl`
   - **Примечание**: Протестировано на Debian, Fedora и RED OS.

3. Соберите проект:
   ```bash
   make clean && make
   ```
   Собирает `gargona` (клиент) и `gargonad` (сервер). Очистка: `make clean`. Пересборка: `make rebuild`.

## Установка клиента
```bash
sudo dpkg -i ./gargona_1.7.0_amd64.deb
```

## Установка сервера
```bash
sudo dpkg -i ./gargonad_1.7.0_amd64.deb
```

### Использование
```sh
gargona [-v] [-e|--exec] [-h|--help] <command> [arguments]
```
#### Генерация ключей
```bash
sudo gargona genkeys
```
- Генерирует пару RSA-ключей в `/etc/gargona/`, создавая `hash.pub` (публичный ключ) и `hash.key` (приватный ключ), где `hash` — base64-кодированный хеш публичного ключа.
- `hash` в имени файла `hash.pub` используется для указания в команде listen от кого получать сообщения, если не указать то будут получены сообщения для всех ключей `*.pub` из `/etc/gargona/`
- для того чтобы получатель смог получить и расшифровать сообщение он должен иметь приватный ключ `hash.key` отправителя в `/etc/gargona/`, передачу ключа вы должны осуществить сами.
- **Права на ключи**: Приватные ключи (`*.key`) должны быть доступны только владельцу (`chmod 600`). Публичные ключи (`*.pub`) могут быть доступны для чтения (`chmod 644`). Проверьте права:
  ```bash
  ls -la /etc/gargona
  ```

#### Отправка сообщения
```bash
gargona send "ГГГГ-ММ-ДД ЧЧ:ММ:СС" "ГГГГ-ММ-ДД ЧЧ:ММ:СС" "Ваше сообщение" "recipient.pub"
```
- Используйте `-` для `<message>`, чтобы читать из stdin.
- Файл публичного ключа — имя файла в `/etc/gargona/`, например, `RWTPQzuhzBw=.pub`.
- Примеры:
  ```bash
  gargona send "2025-09-30 23:55:00" "2025-12-30 12:00:00" "Секретное сообщение для RWTPQzuhzBw=" "RWTPQzuhzBw=.pub"
  ```
  ```bash
  cat message.txt | gargona send "2025-09-30 23:55:00" "2025-12-30 12:00:00" - "RWTPQzuhzBw=.pub"
  ```

#### Прослушивание сообщений
```bash
gargona listen <режим> [<count>] [pubkey_hash_b64]
```
- Режимы:
  - `live`:   Только активные сообщения (`unlock_at <= now`).
  - `all`:    Все неистёкшие сообщения, включая заблокированные.
  - `lock`:   Только заблокированные сообщения (`unlock_at > now`).
  - `single`: Только активные сообщения для указанного `pubkey_hash_b64`.
  - `last`:   Самое недавнее [<count>] сообщение(я) для указанного `pubkey_hash_b64` (count по умолчанию 1).
  - `new`:    Только новые сообщения, полученные после соединения, опционально фильтруются по хешу публичного ключа b64 
- Если указан `pubkey_hash_b64`, фильтрует по нему (обязателен для `single` и `last`).
- Примеры:
  ```bash
  gargona listen single RWTPQzuhzBw=
  gargona listen last RWTPQzuhzBw=    # Получает последнее 1 сообщение
  gargona listen last 3 RWTPQzuhzBw=  # Получает последние 3 сообщения
  gargona listen new RWTPQzuhzBw=     # Получает только новые сообщения с момента подключения 
  gargona listen new                  # Получает только новые сообщения для всех ключей с момента подключения
  gargona -e listen new RWTPQzuhzBw=  # Прослушивает новые сообщения и выполняет их как системные команды
  ```

#### Запуск сервера
```bash
gargonad [-v] [-h|--help]
```
- Используйте `-h` или `--help` для справки по настройке.
- Сервер читает настройки из `/etc/gargona/gargonad.conf` или использует значения по умолчанию (порт: 5555, макс. алертов: 1024, макс. клиентов: 100).

### Конфигурация

#### Конфигурация клиента
Файл `/etc/gargona/gargona.conf` содержит настройки сервера:
```ini
[server]
ip = 64.188.70.158
port = 7777
```

#### Конфигурация сервера
Отредактируйте `/etc/gargona/gargonad.conf`:
```ini
[server]
port = 7777
MAX_ALERTS = 2000
MAX_CLIENTS = 100
max_message_size = 5242880
```
- **port**: TCP-порт (по умолчанию: 5555).
- **MAX_ALERTS**: Макс. алертов на получателя (по умолчанию: 1024).
- **MAX_CLIENTS**: Макс. одновременных подключений (по умолчанию: 100).
- **max_message_size**: Макс. размер сообщения в байтах (по умолчанию: 5242880, 5 МБ).
- Если файл отсутствует, используются значения по умолчанию.

Логи записываются в `gargona.log` с ротацией при превышении 10 МБ.

### Планы на будущее

Gargona эффективно работает с одним сервером. В планах — зеркалирование серверов (репликация) без внешних сервисов (Redis, PostgreSQL) для скорости, децентрализации и надёжности. Возможные подходы: протокол gossip для peer-to-peer синхронизации или лёгкий консенсус (например, адаптированный Raft). Также рассматриваются леджеры, вдохновлённые блокчейном (без майнинга), или CRDT для бесшовной синхронизации. Приветствуются предложения!

[contributing.md](contributing.md) 

#### More examples:
```sh
# send
lsblk | gargona send "2025-09-28 21:44:00" "2025-12-30 12:00:00" - "RWTPQzuhzBw=.pub"
```
```
Server response: Alert added successfully
```
```sh
# get
gargona listen last RWTPQzuhzBw=
```
```
Received message: Pubkey_Hash=RWTPQzuhzBw=
Metadata: Create=2025-10-08 08:39:52, Unlock=2025-09-28 18:44:00, Expire=2025-12-30 09:00:00
Decrypted message: 
NAME        MAJ:MIN RM   SIZE RO TYPE  MOUNTPOINTS
sda           8:0    0 931.5G  0 disk  
└─sda1        8:1    0 931.5G  0 part  /mnt/share
sdb           8:16   0  14.6T  0 disk  
└─sdb1        8:17   0  14.6T  0 part  /mnt/megaraid
nvme1n1     259:0    0 476.9G  0 disk  
├─nvme1n1p1 259:5    0   512M  0 part  
├─nvme1n1p2 259:6    0 197.1G  0 part  
│ └─md0       9:0    0 196.9G  0 raid1 /
├─nvme1n1p3 259:7    0  27.8G  0 part  [SWAP]
└─nvme1n1p4 259:8    0 251.6G  0 part  /mnt/new_free
nvme0n1     259:1    0 476.9G  0 disk  
├─nvme0n1p1 259:2    0   197G  0 part  
│ └─md0       9:0    0 196.9G  0 raid1 /
├─nvme0n1p2 259:3    0   512M  0 part  /boot/efi
└─nvme0n1p3 259:4    0 279.4G  0 part  /mnt/backup
```
```sh
# send command message
gargona send "2025-10-05 18:42:00" "2026-10-09 09:00:00" "echo \$(date)" "RWTPQzuhzBw=.pub"
```
```
Server response: Alert added successfully
```
```sh
# listen execute command message
gargona -e listen new RWTPQzuhzBw=
```
```
Server response: Subscribed to new for the specified key
Received message: Pubkey_Hash=RWTPQzuhzBw=
Metadata: Create=2025-10-11 19:32:49, Unlock=2025-10-05 15:42:00, Expire=2026-10-09 06:00:00
Executing command: echo $(date)
Sat Oct 11 10:32:49 PM MSK 2025
Command return code: 0
```

**Hack for the most patient** — if you want not only to run a command on a remote host but also to receive its output, do it like this.
Of course this won't work without your keys — security-wise that's fine.

```bash
gargona send "2025-09-28 21:44:00" "2025-12-30 12:00:00" "iostat -d | \
gargona send \"2025-09-28 21:44:00\" \"2025-12-30 12:00:00\" - \"RWTPQzuhzBw=.pub\"" "IcUimbs6LZY=.pub"
```

In other words, we wrap execution and the return-send of the command output in a single message.

If we listen on that channel:

```bash
gargona listen new RWTPQzuhzBw=
gargona listen last RWTPQzuhzBw=
```

we immediately get a reply:

```text
Received message: Pubkey_Hash=RWTPQzuhzBw=
Metadata: Create=2025-10-11 22:02:43, Unlock=2025-09-28 18:44:00, Expire=2025-12-30 09:00:00
Decrypted message: Linux 6.5.11-8-pve     10/12/2025     _x86_64_    (32 CPU)

Device             tps    kB_read/s    kB_wrtn/s    kB_dscd/s    kB_read    kB_wrtn    kB_dscd
dm-0              0.00         0.00         0.00         0.00       3728        592          0
dm-1              5.56         3.42        37.17        26.21    4600825   50070268   35299440
dm-10             0.00         0.00         0.00         0.00       5252          0          0
dm-2              0.01         0.05         0.00         0.00      66992          0          0
dm-3              0.76        48.46         0.00         0.00   65274344          0          0
dm-4              0.76        48.46         0.00         0.00   65273896          0          0
dm-5              0.00         0.00         0.00         0.00        448          0          0
dm-6              0.00         0.00         0.00         0.00        796          0          0
dm-7              0.00         0.00         0.00         0.00       3580          0          0
dm-8              0.00         0.00         0.00         0.00       1704          0          0
dm-9              1.46        93.42         0.00         0.00  125833756          0          0
nvme0n1           4.58       128.81        37.17        27.74  173499271   50070861   37368240
sda             278.18      8538.20      1390.09         0.00 11500309619 1872349383          0
```


