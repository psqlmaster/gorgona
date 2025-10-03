# Contributing to Gargona

[Русская версия](#вклад-в-gargona) | English Version

Thank you for your interest in contributing to **Gargona**, an encrypted time-locked messaging system! We welcome contributions from the community to improve security, performance, documentation, and usability. This guide outlines how you can contribute, from submitting bug reports to proposing new features.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Submitting Code Changes](#submitting-code-changes)
- [Development Setup](#development-setup)
- [Coding Guidelines](#coding-guidelines)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Contact](#contact)

## Code of Conduct

By participating in this project, you agree to abide by the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/0/code_of_conduct/). We are committed to fostering an inclusive and respectful community.

## How to Contribute

### Reporting Bugs

If you find a bug, please report it via GitHub Issues:

1. Check if the issue already exists in the [issue tracker](https://github.com/psqlmaster/gargona/issues).
2. Create a new issue with a clear title (e.g., "Server crashes on invalid SEND command").
3. Include:
   - Steps to reproduce the bug.
   - Expected and actual behavior.
   - Environment details (OS, OpenSSL version, compiler).
   - Relevant logs (e.g., from `gargonad.log`).
4. Use the provided issue template if available.

### Suggesting Features

We welcome ideas for new features, such as replication or new subscription modes! To propose a feature:

1. Open a GitHub Issue with the label "enhancement."
2. Describe the feature, its use case, and potential implementation ideas.
3. Reference the [**"Future Plans"**](./readme.md#future-plans) section in readme.md if relevant.

### Submitting Code Changes

To contribute code (bug fixes, features, or improvements):

1. Fork the repository and create a branch for your changes (`git checkout -b feature/your-feature-name`).
2. Follow the [Coding Guidelines](#coding-guidelines) and ensure tests pass.
3. Commit your changes with clear messages (e.g., "Fix buffer overflow in SEND parsing").
4. Push to your fork and submit a pull request (PR) to the `main` branch.
5. Reference the related issue in your PR description (e.g., "Fixes #123").

## Development Setup

To set up the development environment:

1. Clone the repository:
   ```bash
   git clone https://github.com/psqlmaster/gargona.git
   cd gargona
   ```
2. Install dependencies (OpenSSL required):
   - Debian/Ubuntu: `sudo apt install libssl-dev`
   - Fedora: `sudo dnf install openssl-devel`
   - REDOS: `sudo yum install openssl11 openssl11-devel`
   - macOS: `brew install openssl`
3. Build the project:
   ```bash
   make clean && make
   ```
4. Test your setup by running:
   ```bash
   ./gargonad -h
   ./gargona genkeys
   ```

## Coding Guidelines

To maintain code quality and consistency:

- **Language**: Use C99 standard for compatibility.
- **Style**: Follow the [Linux Kernel Coding Style](https://www.kernel.org/doc/html/latest/process/coding-style.html) (tabs, 80-column limit, clear function names).
  - Run `clang-format` with the provided `.clang-format` file (if available) or use `indent -kr`.
- **Comments**: Use `/* */` for comments, in English, with clear explanations (e.g., `/* Parse SEND command, validate format */`).
- **Error Handling**: Always check return values (e.g., `fopen`, `malloc`) and log errors to `gargona.log`.
- **Security**: Avoid buffer overflows, use `strncpy` over `strcpy`, and validate all inputs.
- **Logging**: Use UTC timestamps (`[YYYY-MM-DDThh:mm:ssZ]`) via `get_utc_time_str` in `gargonad.c`.

Example:
```c
/* Validate and parse SEND command */
if (strncmp(buffer, "SEND|", 5) != 0) {
    char time_str[32];
    get_utc_time_str(time_str, sizeof(time_str));
    fprintf(log_file, "%s Invalid command from %d: %.*s\n", time_str, sd, valread, buffer);
    fflush(log_file);
    return -1;
}
```

## Testing

We aim for robust code with high test coverage:

1. Write unit tests for new functions in `tests/` using CMocka (planned, check issues for status).
2. Run existing tests (if any):
   ```bash
   make test
   ```
3. Test manually:
   - Generate keys: `./gargona genkeys`
   - Send a message: `./gargona send "2025-10-03 12:00:00" "2026-10-03 12:00:00" "Test" "hash.pub"`
   - Listen: `./gargona listen single hash`
   - Check logs: `tail -f gargona.log`
4. Ensure no memory leaks (use `valgrind`):
   ```bash
   valgrind --leak-check=full ./gargonad
   ```

## Pull Request Process

1. Ensure your code follows the [Coding Guidelines](#coding-guidelines).
2. Include tests for new functionality or bug fixes.
3. Update documentation (README.md, inline comments) if needed.
4. Submit your PR with a clear description, referencing issues (e.g., "Fixes #123: Add TLS support").
5. A maintainer will review your PR. Be ready to address feedback.
6. After approval, your changes will be merged into `main`.

## Contact

For questions or discussions:
- Open an issue on GitHub.
- Reach out to the maintainer: [psqlmaster](https://github.com/psqlmaster).
- Join discussions in the [Issues](https://github.com/psqlmaster/gargona/issues) section.

Thank you for contributing to Gargona’s mission of secure, time-locked messaging!

---

# Вклад в Gargona

[English Version](#contributing-to-gargona) | Русская версия

Спасибо за ваш интерес к проекту **Gargona**, системе зашифрованного алертинга с временной блокировкой! Мы приветствуем вклад сообщества в улучшение безопасности, производительности, документации и удобства использования. Это руководство описывает, как вы можете внести свой вклад: от сообщений об ошибках до предложений новых функций.

## Содержание

- [Кодекс поведения](#кодекс-поведения)
- [Как внести вклад](#как-внести-вклад)
  - [Сообщение об ошибках](#сообщение-об-ошибках)
  - [Предложение функций](#предложение-функций)
  - [Отправка изменений в коде](#отправка-изменений-в-коде)
- [Настройка разработки](#настройка-разработки)
- [Правила оформления кода](#правила-оформления-кода)
- [Тестирование](#тестирование)
- [Процесс Pull Request](#процесс-pull-request)
- [Контакты](#контакты)

## Кодекс поведения

Участвуя в проекте, вы соглашаетесь соблюдать [Кодекс поведения Contributor Covenant](https://www.contributor-covenant.org/version/2/0/code_of_conduct/). Мы стремимся создать инклюзивное и уважительное сообщество.

## Как внести вклад

### Сообщение об ошибках

Если вы нашли ошибку, сообщите о ней через GitHub Issues:

1. Проверьте, нет ли уже такого вопроса в [трекере](https://github.com/psqlmaster/gargona/issues).
2. Создайте новый issue с понятным заголовком (например, «Сервер падает при неверной команде SEND»).
3. Укажите:
   - Шаги для воспроизведения ошибки.
   - Ожидаемое и фактическое поведение.
   - Детали окружения (ОС, версия OpenSSL, компилятор).
   - Соответствующие логи (например, из `gargonad.log`).
4. Используйте шаблон issue, если он доступен.

### Предложение функций

Мы рады идеям новых функций, таких как репликация или новые режимы подписки! Чтобы предложить функцию:

1. Откройте GitHub Issue с меткой "enhancement".
2. Опишите функцию, её сценарий использования и идеи реализации.
3. Ссылайтесь на раздел [**"Планы на будущее"**](./readme.md#планы-на-будущее) в readme.md, если применимо.

Чтобы внести изменения в код (исправления ошибок, функции или улучшения):

1. Сделайте форк репозитория и создайте ветку для изменений (`git checkout -b feature/название-вашей-функции`).
2. Следуйте [Правилам оформления кода](#правила-оформления-кода) и убедитесь, что тесты проходят.
3. Коммитьте изменения с понятными сообщениями (например, «Исправлен переполнение буфера в парсинге SEND»).
4. Отправьте изменения в свой форк и создайте pull request (PR) в ветку `main`.
5. Укажите связанный issue в описании PR (например, «Исправляет #123»).

## Настройка разработки

Для настройки окружения разработки:

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/psqlmaster/gargona.git
   cd gargona
   ```
2. Установите зависимости (требуется OpenSSL):
   - Debian/Ubuntu: `sudo apt install libssl-dev`
   - Fedora: `sudo dnf install openssl-devel`
   - REDOS: `sudo yum install openssl11 openssl11-devel`
   - macOS: `brew install openssl`
3. Соберите проект:
   ```bash
   make clean && make
   ```
4. Проверьте настройку, запустив:
   ```bash
   ./gargonad -h
   ./gargona genkeys
   ```

## Правила оформления кода

Для поддержания качества и единообразия кода:

- **Язык**: Используйте стандарт C99 для совместимости.
- **Стиль**: Следуйте [стилю кодирования ядра Linux](https://www.kernel.org/doc/html/latest/process/coding-style.html) (табы, лимит 80 символов, понятные имена функций).
  - Используйте `clang-format` с файлом `.clang-format` (если есть) или `indent -kr`.
- **Комментарии**: Используйте `/* */` на английском с ясными пояснениями (например, `/* Парсинг команды SEND, проверка формата */`).
- **Обработка ошибок**: Проверяйте возвращаемые значения (например, `fopen`, `malloc`) и логируйте ошибки в `gargona.log`.
- **Безопасность**: Избегайте переполнений буфера, используйте `strncpy` вместо `strcpy`, валидируйте все входные данные.
- **Логирование**: Используйте UTC-метки времени (`[ГГГГ-ММ-ДДTчч:мм:ссZ]`) через `get_utc_time_str` в `gargonad.c`.

Пример:
```c
/* Проверка и парсинг команды SEND */
if (strncmp(buffer, "SEND|", 5) != 0) {
    char time_str[32];
    get_utc_time_str(time_str, sizeof(time_str));
    fprintf(log_file, "%s Invalid command from %d: %.*s\n", time_str, sd, valread, buffer);
    fflush(log_file);
    return -1;
}
```

## Тестирование

Мы стремимся к надёжному коду с высоким покрытием тестами:

1. Пишите модульные тесты для новых функций в директории `tests/` с использованием CMocka (планируется, следите за issue).
2. Запустите существующие тесты (если есть):
   ```bash
   make test
   ```
3. Тестируйте вручную:
   - Генерация ключей: `./gargona genkeys`
   - Отправка сообщения: `./gargona send "2025-10-03 12:00:00" "2026-10-03 12:00:00" "Тест" "hash.pub"`
   - Прослушивание: `./gargona listen single hash`
   - Проверка логов: `tail -f gargona.log`
4. Проверяйте утечки памяти с помощью `valgrind`:
   ```bash
   valgrind --leak-check=full ./gargonad
   ```

## Процесс Pull Request

1. Убедитесь, что код соответствует [Правилам оформления кода](#правила-оформления-кода).
2. Добавьте тесты для новых функций или исправлений.
3. Обновите документацию (README.md, inline-комментарии), если нужно.
4. Отправьте PR с понятным описанием, ссылаясь на issue (например, «Исправляет #123: Добавлена поддержка TLS»).
5. Мейнтейнер рассмотрит ваш PR. Будьте готовы ответить на обратную связь.
6. После одобрения изменения будут влиты в `main`.

## Контакты

Для вопросов или обсуждений:
- Откройте issue на GitHub.
- Свяжитесь с мейнтейнером: [psqlmaster](https://github.com/psqlmaster).
- Присоединяйтесь к обсуждениям в разделе [Issues](https://github.com/psqlmaster/gargona/issues).

Спасибо за ваш вклад в миссию Gargona — безопасный обмен сообщениями с временной блокировкой!
