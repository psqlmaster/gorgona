#### Contributing to gorgona

Thank you for your interest in contributing to **gorgona**, an encrypted time-locked messaging system! We welcome contributions from the community to improve security, performance, documentation, and usability. This guide outlines how you can contribute, from submitting bug reports to proposing new features.

##### Table of Contents

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

##### Code of Conduct

By participating in this project, you agree to abide by the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/0/code_of_conduct/). We are committed to fostering an inclusive and respectful community.

#### How to Contribute

##### Reporting Bugs

If you find a bug, please report it via GitHub Issues:

1. Check if the issue already exists in the [issue tracker](https://github.com/psqlmaster/gorgona/issues).
2. Create a new issue with a clear title (e.g., "Server crashes on invalid SEND command").
3. Include:
   - Steps to reproduce the bug.
   - Expected and actual behavior.
   - Environment details (OS, OpenSSL version, compiler).
   - Relevant logs (e.g., from `gorgonad.log`).
4. Use the provided issue template if available.

##### Suggesting Features

We welcome ideas for new features, such as replication or new subscription modes! To propose a feature:

1. Open a GitHub Issue with the label "enhancement."
2. Describe the feature, its use case, and potential implementation ideas.
3. Reference the [**"Future Plans"**](./readme.md#future-plans) section in readme.md if relevant.

##### Submitting Code Changes

To contribute code (bug fixes, features, or improvements):

1. Fork the repository and create a branch for your changes (`git checkout -b feature/your-feature-name`).
2. Follow the [Coding Guidelines](#coding-guidelines) and ensure tests pass.
3. Commit your changes with clear messages (e.g., "Fix buffer overflow in SEND parsing").
4. Push to your fork and submit a pull request (PR) to the `main` branch.
5. Reference the related issue in your PR description (e.g., "Fixes #123").

##### Development Setup

To set up the development environment:

1. Clone the repository:
   ```bash
   git clone https://github.com/psqlmaster/gorgona.git
   cd gorgona
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
   ./gorgonad -h
   ./gorgona genkeys
   ```

##### Coding Guidelines

To maintain code quality and consistency:

- **Language**: Use C99 standard for compatibility.
- **Style**: Follow the [Linux Kernel Coding Style](https://www.kernel.org/doc/html/latest/process/coding-style.html) (tabs, 80-column limit, clear function names).
  - Run `clang-format` with the provided `.clang-format` file (if available) or use `indent -kr`.
- **Comments**: Use `/* */` for comments, in English, with clear explanations (e.g., `/* Parse SEND command, validate format */`).
- **Error Handling**: Always check return values (e.g., `fopen`, `malloc`) and log errors to `gorgona.log`.
- **Security**: Avoid buffer overflows, use `strncpy` over `strcpy`, and validate all inputs.
- **Logging**: Use UTC timestamps (`[YYYY-MM-DDThh:mm:ssZ]`) via `get_utc_time_str` in `gorgonad.c`.

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

##### Testing

We aim for robust code with high test coverage:

1. Write unit tests for new functions in `tests/` using CMocka (planned, check issues for status).
2. Run existing tests (if any):
   ```bash
   make test
   ```
3. Test manually:
   - Generate keys: `./gorgona genkeys`
   - Send a message: `./gorgona send "2025-10-03 12:00:00" "2026-10-03 12:00:00" "Test" "hash.pub"`
   - Listen: `./gorgona listen single hash`
   - Check logs: `tail -f gorgona.log`
4. Ensure no memory leaks (use `valgrind`):
   ```bash
   valgrind --leak-check=full ./gorgonad
   ```

#### Pull Request Process

1. Ensure your code follows the [Coding Guidelines](#coding-guidelines).
2. Include tests for new functionality or bug fixes.
3. Update documentation (README.md, inline comments) if needed.
4. Submit your PR with a clear description, referencing issues (e.g., "Fixes #123: Add TLS support").
5. A maintainer will review your PR. Be ready to address feedback.
6. After approval, your changes will be merged into `main`.

##### Contact

For questions or discussions:
- Open an issue on GitHub.
- Reach out to the maintainer: [psqlmaster](https://github.com/psqlmaster).
- Join discussions in the [Issues](https://github.com/psqlmaster/gorgona/issues) section.

Thank you for contributing to gorgona’s mission of secure, time-locked messaging!

