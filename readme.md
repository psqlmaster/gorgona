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
- **Key Management**: Generates RSA key pairs named by the public key’s hash for secure sharing and local private key storage.
- **Flexible Subscription Modes**: Listen in "live" (unlocked messages), "all" (including metadata for locked messages), "lock" (locked messages only), or "single" (specific recipient).
- **Efficient Storage**: Uses a ring buffer, limiting alerts per recipient to a configurable number (default: 1024), automatically removing the oldest or expired messages.
- **Decentralized Design**: Users control keys, and the lightweight server supports self-hosting.
- **Fast and Lightweight**: Built with OpenSSL, requiring minimal dependencies.
- **Tamper-Proof**: GCM authentication tags and RSA-OAEP padding protect against tampering.

**Advantages**:
- **Uncompromised Security**: Messages remain confidential even if the server is breached.
- **Versatile Use Cases**: Perfect for personal reminders, corporate alerts, whistleblower tools, or automated data releases.
- **Scalable Architecture**: Simple TCP server handles multiple clients (default: 100, configurable), with potential for load balancing.
- **No Third-Party Reliance**: Operates locally or via direct client-server communication.
- **Creative Applications**: Build time capsules, gamified messaging, or secure delayed backups.

## Quick Start
```bash
git clone https://github.com/psqlmaster/gargona.git
cd gargona
./gargona listen all
```

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/psqlmaster/gargona.git
   cd gargona
   ```

2. Install dependencies (OpenSSL required):
   - On Debian/Ubuntu: `sudo apt install libssl-dev`
   - On Fedora: `sudo dnf install openssl-devel`
   - On REDOS: `sudo yum install openssl11 openssl11-devel`
   - On macOS: `brew install openssl`
   - **Note**: The project has been tested on Debian, Fedora, and RED OS.

3. Build the project:
   ```
   make clean && make
   ```
   Builds both `gargona` (client) and `gargonad` (server). Clean: `make clean`. Rebuild: `make rebuild`.

### Usage

#### Generate Keys
```
./gargona genkeys
```
- Creates `hash.pub` and `hash.key` files, where `hash` is the base64-encoded hash of the public key.

#### Send Message
```
./gargona send "YYYY-MM-DD HH:MM:SS" "YYYY-MM-DD HH:MM:SS" "Your message" "recipient.pub"
```
- Example:
  ```
  ./gargona send "2025-09-25 09:00:00" "2026-09-30 09:00:00" "Secret message" "RWTPQzuhzBw=.pub"
  ```

#### Listen for Messages
```
./gargona listen <mode> [pubkey_hash_b64]
```
- Modes: `live` (unlocked messages), `all` (all non-expired messages), `lock` (locked messages), `single` (specific recipient, requires pubkey_hash_b64).
- Example:
  ```
  ./gargona listen single RWTPQzuhzBw=
  ```

#### Run Server
```
./gargonad [-h|--help]
```
- Use `-h` or `--help` to display server configuration and usage details.
- The server reads settings from `./gargonad.conf` or uses defaults (port: 5555, max alerts: 1024, max clients: 100).

### Configuration

#### Client Configuration
Edit `gargona.conf` in the client’s working directory to configure server connection settings:
```
[server]
ip = 64.188.70.158
port = 7777
```

#### Server Configuration
Edit `gargonad.conf` in the server’s working directory to configure server settings:
```
[server]
port = 7777
MAX_ALERTS = 2000
MAX_CLIENTS = 100
```
- **port**: The TCP port the server listens on (default: 5555).
- **MAX_ALERTS**: Maximum number of alerts per recipient (default: 1024).
- **MAX_CLIENTS**: Maximum number of simultaneous client connections (default: 100).
- If the file is missing or parameters are not specified, defaults are used.

Logs are written to `gargona.log`, with rotation when the file exceeds 10 MB.

### Future Plans

Gargona is a robust solution for encrypted, time-locked messaging with a single server. I’m exploring server mirroring (replication) without external services like Redis or PostgreSQL. The goal is a fast, decentralized, and reliable system—potentially using a gossip protocol for peer-to-peer synchronization or a lightweight consensus mechanism like Raft. Ideas include blockchain-inspired ledgers (without crypto mining) or conflict-free replicated data types (CRDTs) for seamless data syncing. This would allow a network of servers to mirror messages in real-time, ensuring high availability. Contributions and suggestions are welcome!

See [contributing.md](contributing.md) for how to contribute to Gargona.
---

## Gargona: Система зашифрованного алертинга с временной блокировкой

[English Version](#gargona-encrypted-time-locked-messaging-system) | Русская версия

### Введение

Gargona — это безопасная система обмена сообщениями, позволяющая отправлять зашифрованные сообщения, которые становятся доступными в заданное время и удаляются после истечения срока действия. Сообщения шифруются от отправителя до получателя с использованием RSA для обмена ключами и AES-GCM для содержимого. Сервер хранит только зашифрованные данные, не имея доступа к их содержимому, что обеспечивает конфиденциальность. Gargona идеально подходит для передачи чувствительной информации, планирования уведомлений или отложенной доставки сообщений (например, временных капсул или экстренного раскрытия данных).

Проект включает клиент (`gargona`) для генерации ключей, отправки сообщений и прослушивания алертов, а также сервер (`gargonad`) для их хранения и доставки.

### Функции

- **Сквозное шифрование**: Сообщения шифруются на клиенте и расшифровываются только получателем с приватным ключом.
- **Временная блокировка**: Сообщения становятся доступными в заданное время (`unlock_at`) и удаляются после (`expire_at`).
- **Конфиденциальность**: Сервер работает только с зашифрованными данными, не имея доступа к содержимому.
- **Управление ключами**: Генерирует пары RSA-ключей, названные по хешу публичного ключа для удобного обмена и безопасного хранения.
- **Гибкие режимы подписки**: Поддерживает "live" (доступные сообщения), "all" (все сообщения, включая метаданные), "lock" (только заблокированные сообщения) и "single" (для конкретного получателя).
- **Эффективное хранение**: Кольцевой буфер ограничивает количество сообщений на получателя до настраиваемого значения (по умолчанию: 1024), удаляя старые или истекшие.
- **Децентрализованный дизайн**: Пользователи контролируют ключи, сервер лёгкий и подходит для самостоятельного хостинга.
- **Быстрота и лёгкость**: Использует OpenSSL, без тяжёлых зависимостей.
- **Защита от подделки**: Теги аутентификации GCM и OAEP-паддинг в RSA предотвращают вмешательство.

**Преимущества**:
- **Безопасность**: Сообщения остаются конфиденциальными даже при компрометации сервера.
- **Универсальность**: Подходит для личных напоминаний, корпоративных уведомлений, инструментов для информаторов или автоматической отправки данных.
- **Масштабируемость**: Простой TCP-сервер поддерживает множество клиентов (по умолчанию: 100, настраивается) и может быть расширен.
- **Без внешних сервисов**: Работает локально или через прямое взаимодействие клиент-сервер.
- **Креативные сценарии**: Временные капсулы, игровые системы обмена сообщениями или безопасные резервные копии.

## Быстрый старт
```bash
git clone https://github.com/psqlmaster/gargona.git
cd gargona
./gargona listen all
```

### Установка

1. Клонируйте репозиторий:
   ```
   git clone https://github.com/psqlmaster/gargona.git
   cd gargona
   ```

2. Установите зависимости (требуется OpenSSL):
   - На Debian/Ubuntu: `sudo apt install libssl-dev`
   - На Fedora: `sudo dnf install openssl-devel`
   - На REDOS: `sudo yum install openssl11 openssl11-devel`
   - На macOS: `brew install openssl`
   - **Примечание**: Проект протестирован на Debian, Fedora и RED OS.

3. Соберите проект:
   ```
   make clean && make
   ```
   Собирает `gargona` (клиент) и `gargonad` (сервер). Очистка: `make clean`. Пересборка: `make rebuild`.

### Использование

#### Генерация ключей
```
./gargona genkeys
```
- Создаёт файлы `hash.pub` и `hash.key`, где `hash` — base64-кодированный хеш публичного ключа.

#### Отправка сообщения
```
./gargona send "ГГГГ-ММ-ДД ЧЧ:ММ:СС" "ГГГГ-ММ-ДД ЧЧ:ММ:СС" "Ваше сообщение" "recipient.pub"
```
- Пример:
  ```
  ./gargona send "2025-09-25 09:00:00" "2026-09-30 09:00:00" "Секретное сообщение" "RWTPQzuhzBw=.pub"
  ```

#### Прослушивание сообщений
```
./gargona listen <режим> [pubkey_hash_b64]
```
- Режимы: `live` (доступные сообщения), `all` (все сообщения, включая метаданные), `lock` (только заблокированные), `single` (хеш конкретного получателя, обязателен).
- Пример:
  ```
  ./gargona listen single RWTPQzuhzBw=
  ```

#### Запуск сервера
```
./gargonad [-h|--help]
```
- Используйте `-h` или `--help` для отображения справки по настройке сервера.
- Сервер читает настройки из `./gargonad.conf` или использует значения по умолчанию (порт: 5555, макс. алертов: 1024, макс. клиентов: 100).

### Конфигурация

#### Конфигурация клиента
Отредактируйте `gargona.conf` в рабочей директории клиента для настройки подключения к серверу:
```
[server]
ip = 64.188.70.158
port = 7777
```

#### Конфигурация сервера
Отредактируйте `gargonad.conf` в рабочей директории сервера для настройки параметров:
```
[server]
port = 7777
MAX_ALERTS = 2000
MAX_CLIENTS = 100
```
- **port**: TCP-порт сервера (по умолчанию: 5555).
- **MAX_ALERTS**: Максимальное количество алертов на получателя (по умолчанию: 1024).
- **MAX_CLIENTS**: Максимальное количество одновременных клиентских подключений (по умолчанию: 100).
- Если файл отсутствует или параметры не указаны, используются значения по умолчанию.

Логи записываются в `gargona.log` с ротацией при превышении размера в 10 МБ.

### Планы на будущее

Gargona уже эффективно справляется с задачей зашифрованного алертинга с одним сервером. Я работаю над созданием зеркалирования серверов (репликации) без внешних сервисов, таких как Redis или PostgreSQL. Цель — обеспечить высокую скорость, децентрализацию и надёжность. Возможные подходы: протокол gossip для синхронизации между серверами в режиме peer-to-peer или лёгкий механизм консенсуса, например, адаптированный Raft. Другие идеи включают леджеры, вдохновлённые блокчейном (без майнинга), или типы данных с бесконфликтной репликацией (CRDT) для бесшовной синхронизации. Приветствуются любые предложения по улучшению!

Информация о том, как внести свой вклад в Gargona, см. на странице [contributing.md](contributing.md).
