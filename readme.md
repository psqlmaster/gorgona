# Gargona: Encrypted Time-Locked Messaging System

[Русская версия](#gargona-система-зашифрованного-алертинга-с-временной-блокировкой) | [English Version](#gargona-encrypted-time-locked-messaging-system)

---

## Gargona: Encrypted Time-Locked Messaging System

### Introduction

Gargona, inspired by the mythical guardians that watch over secrets, is a secure messaging system for sending encrypted messages that unlock at a specific time and expire after a set period. Using RSA for key exchange and AES-GCM for content encryption, Gargona ensures end-to-end privacy. The server stores only encrypted messages, unable to access their content, making it ideal for sensitive communications, scheduled notifications, or delayed message releases (e.g., time capsules or emergency data sharing).

The project includes a client for key generation, sending messages, and listening for alerts, and a server for securely storing and delivering them.

### Features

- **End-to-End Encryption**: Messages are encrypted on the client and decrypted only by the recipient with their private key.
- **Time-Locked Delivery**: Messages unlock at a specified `unlock_at` time and expire at `expire_at`.
- **Privacy-First**: The server handles only encrypted data, ensuring no access to message content.
- **Key Management**: Generates RSA key pairs named by the public key’s hash for secure sharing and local private key storage.
- **Flexible Subscription Modes**: Listen in "live" (unlocked messages), "all" (including metadata for locked messages), or "single" (specific recipient).
- **Efficient Storage**: Uses a ring buffer, limiting alerts per recipient to 1024, automatically removing the oldest or expired messages.
- **Decentralized Design**: Users control keys, and the lightweight server supports self-hosting.
- **Fast and Lightweight**: Built with OpenSSL, requiring minimal dependencies.
- **Tamper-Proof**: GCM authentication tags and RSA-OAEP padding protect against tampering.

**Advantages**:
- **Uncompromised Security**: Messages remain confidential even if the server is breached.
- **Versatile Use Cases**: Perfect for personal reminders, corporate alerts, whistleblower tools, or automated data releases.
- **Scalable Architecture**: Simple TCP server handles multiple clients, with potential for load balancing.
- **No Third-Party Reliance**: Operates locally or via direct client-server communication.
- **Creative Applications**: Build time capsules, gamified messaging, or secure delayed backups.

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/gargona.git
   cd gargona
   ```

2. Install dependencies (OpenSSL required):
   - On Debian, Ubuntu: `sudo apt install libssl-dev`
   - On macOS: `brew install openssl`

3. Build the project:
   ```
   gcc -g -o gargona gargona.c alert_send.c alert_listen.c config.c encrypt.c -lssl -lcrypto
   gcc -g -o gargonad gargonad.c encrypt.c -lssl -lcrypto
   ```

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
- Modes: `live` (unlocked messages), `all` (all messages, including metadata), `single` (specific recipient hash).
- Example:
  ```
  ./gargona listen single RWTPQzuhzBw=
  ```

#### Run Server
```
./gargonad
```

### Configuration

Edit `gargona.conf` to configure the server. For testing, use:
```
[server]
ip = 64.188.70.158
port = 7777
```

### Future Plans

Gargona is a robust solution for encrypted, time-locked messaging with a single server. I’m exploring server mirroring (replication) without external services like Redis or PostgreSQL. The goal is a fast, decentralized, and reliable system—potentially using a gossip protocol for peer-to-peer synchronization or a lightweight consensus mechanism like Raft. Ideas include blockchain-inspired ledgers (without crypto mining) or conflict-free replicated data types (CRDTs) for seamless data syncing. This would allow a network of servers to mirror messages in real-time, ensuring high availability. Contributions and suggestions are welcome!

---

## Gargona: Система зашифрованного алертинга с временной блокировкой

[English Version](#gargona-encrypted-time-locked-messaging-system) | [Русская версия](#gargona-система-зашифрованного-алертинга-с-временной-блокировкой)

### Введение

Gargona, названная в честь мифических стражей, охраняющих тайны, — это безопасная система обмена сообщениями, позволяющая отправлять зашифрованные сообщения, которые становятся доступными в заданное время и удаляются после истечения срока действия. Сообщения шифруются от отправителя до получателя с использованием RSA для обмена ключами и AES-GCM для содержимого. Сервер хранит только зашифрованные данные, не имея доступа к их содержимому, что обеспечивает конфиденциальность. Gargona идеально подходит для передачи чувствительной информации, планирования уведомлений или отложенной доставки сообщений (например, временных капсул или экстренного раскрытия данных).

Проект включает клиент для генерации ключей, отправки сообщений и прослушивания алертов, а также сервер для их хранения и доставки.

### Функции

- **Сквозное шифрование**: Сообщения шифруются на клиенте и расшифровываются только получателем с приватным ключом.
- **Временная блокировка**: Сообщения становятся доступными в заданное время (`unlock_at`) и удаляются после (`expire_at`).
- **Конфиденциальность**: Сервер работает только с зашифрованными данными, не имея доступа к содержимому.
- **Управление ключами**: Генерирует пары RSA-ключей, названные по хешу публичного ключа для удобного обмена и безопасного хранения.
- **Гибкие режимы подписки**: Поддерживает "live" (доступные сообщения), "all" (все сообщения, включая метаданные), и "single" (для конкретного получателя).
- **Эффективное хранение**: Кольцевой буфер ограничивает количество сообщений на получателя до 1024, удаляя старые или истекшие.
- **Децентрализованный дизайн**: Пользователи контролируют ключи, сервер лёгкий и подходит для самостоятельного хостинга.
- **Быстрота и лёгкость**: Использует OpenSSL, без тяжёлых зависимостей.
- **Защита от подделки**: Теги аутентификации GCM и OAEP-паддинг в RSA предотвращают вмешательство.

**Преимущества**:
- **Безопасность**: Сообщения остаются конфиденциальными даже при компрометации сервера.
- **Универсальность**: Подходит для личных напоминаний, корпоративных уведомлений, инструментов для информаторов или автоматической отправки данных.
- **Масштабируемость**: Простой TCP-сервер поддерживает множество клиентов и может быть расширен.
- **Без внешних сервисов**: Работает локально или через прямое взаимодействие клиент-сервер.
- **Креативные сценарии**: Временные капсулы, игровые системы обмена сообщениями или безопасные резервные копии.

### Установка

1. Клонируйте репозиторий:
   ```
   git clone https://github.com/yourusername/gargona.git
   cd gargona
   ```

2. Установите зависимости (требуется OpenSSL):
   - На Ubuntu: `sudo apt install libssl-dev`
   - На macOS: `brew install openssl`

3. Соберите проект:
   ```
   gcc -g -o gargona gargona.c alert_send.c alert_listen.c config.c encrypt.c -lssl -lcrypto
   gcc -g -o gargonad gargonad.c encrypt.c -lssl -lcrypto
   ```

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
- Режимы: `live` (доступные сообщения), `all` (все сообщения, включая метаданные), `single` (хеш конкретного получателя).
- Пример:
  ```
  ./gargona listen single RWTPQzuhzBw=
  ```

#### Запуск сервера
```
./gargonad
```

### Конфигурация

Отредактируйте `gargona.conf` для настройки сервера. Для тестирования используйте:
```
[server]
ip = 64.188.70.158
port = 7777
```

### Планы на будущее

Gargona уже эффективно справляется с задачей зашифрованного алертинга с одним сервером. Я работаю над созданием зеркалирования серверов (репликации) без внешних сервисов, таких как Redis или PostgreSQL. Цель — обеспечить высокую скорость, децентрализацию и надёжность. Возможные подходы: протокол gossip для синхронизации между серверами в режиме peer-to-peer или лёгкий механизм консенсуса, например, адаптированный Raft. Другие идеи включают леджеры, вдохновлённые блокчейном (без майнинга), или типы данных с бесконфликтной репликацией (CRDT) для бесшовной синхронизации. Приветствуются любые предложения по улучшению!

