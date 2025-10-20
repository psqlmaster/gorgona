# Compiler and flags
CC = gcc
CFLAGS = -g -std=c99 -Wall -Icommon -Iclient -DVERSION=\"$(VERSION)\" -pthread -D_XOPEN_SOURCE=700 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lssl -lcrypto
TEST_CFLAGS = $(CFLAGS) $(shell pkg-config --cflags check)
TEST_LDFLAGS = $(LDFLAGS) $(shell pkg-config --libs check)

# Version definition from Git tag
VERSION = $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' | tr -d '\n' || echo "0.0.0")

# Default changelog message (used if no commits or CHANGELOG_MSG is not set)
DEFAULT_CHANGELOG_MSG = New release of gorgona client and server.

# Source files
gorgona_SRC = client/gorgona.c client/alert_send.c client/alert_listen.c client/config.c common/encrypt.c
gorgonaD_SRC = server/gorgonad.c server/gorgona_utils.c server/server_handler.c server/snowflake.c server/alert_db.c common/encrypt.c
TEST_SRC = test/test_config.c test/test_alert_send.c test/test_alert_listen.c test/test_gorgona.c

# Object files
gorgona_OBJ = $(gorgona_SRC:.c=.o)
gorgonaD_OBJ = $(gorgonaD_SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o)

# Test object files (без дублирующих модулей)
TEST_CONFIG_OBJ = test/test_config.o client/alert_send.o client/alert_listen.o client/config.o common/encrypt.o
TEST_ALERT_SEND_OBJ = test/test_alert_send.o client/alert_send.o client/alert_listen.o client/config.o common/encrypt.o
TEST_ALERT_LISTEN_OBJ = test/test_alert_listen.o client/alert_send.o client/alert_listen.o client/config.o common/encrypt.o
TEST_GORGONA_OBJ = test/test_gorgona.o

# Test executables
TEST_EXEC = test/test_config test/test_alert_send test/test_alert_listen test/test_gorgona

# Targets
all: gorgona gorgonad

# Build gorgona
gorgona: $(gorgona_OBJ)
	$(CC) $(gorgona_OBJ) -o gorgona $(LDFLAGS)

# Build gorgonad
gorgonad: $(gorgonaD_OBJ)
	$(CC) $(gorgonaD_OBJ) -o gorgonad $(LDFLAGS)

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Test targets
test: $(TEST_EXEC)
	@echo "Running all tests..."
	@for test in $(TEST_EXEC); do \
		if [ -f "$$test" ]; then \
			echo "Running $$test..."; \
			./$$test || { echo "$$test failed"; exit 1; }; \
		else \
			echo "Test $$test not found!"; \
			exit 1; \
		fi; \
	done
	@echo "All tests completed successfully."

test/test_config: $(TEST_CONFIG_OBJ)
	$(CC) $^ -o $@ $(TEST_LDFLAGS)

test/test_alert_send: $(TEST_ALERT_SEND_OBJ)
	$(CC) $^ -o $@ $(TEST_LDFLAGS)

test/test_alert_listen: $(TEST_ALERT_LISTEN_OBJ)
	$(CC) $^ -o $@ $(TEST_LDFLAGS)

test/test_gorgona: $(TEST_GORGONA_OBJ)
	$(CC) $^ -o $@ $(TEST_LDFLAGS)

# Update debian/changelog with commit messages
deb-changelog:
	@echo "Updating debian/changelog with version $(VERSION)"
	@CURRENT_TAG=$$(git --no-pager describe --tags --abbrev=0 2>/dev/null); \
	CURRENT_TAG_OUT=$$(echo "$$CURRENT_TAG" | sed 's/^v//' | tr -d '\n' || echo "0.0.0"); \
	PREV_TAG=$$(git --no-pager tag --sort=-v:refname | grep -A 1 "$$CURRENT_TAG" | tail -n 1); \
	CHANGELOG_MESSAGE=$$(git --no-pager log --pretty="* %s" "$$PREV_TAG..$$CURRENT_TAG" 2>/dev/null | sort -u); \
	if [ -z "$$CHANGELOG_MESSAGE" ]; then CHANGELOG_MESSAGE="$(DEFAULT_CHANGELOG_MSG)"; fi; \
	{ \
		echo "gorgona ($$CURRENT_TAG_OUT) stable; urgency=medium"; \
		echo ""; \
		echo "$$CHANGELOG_MESSAGE" | sed 's/^/  /'; \
		echo ""; \
		echo " -- Aleksandr Scheglov <globalalek@gmail.com> $$(date -R)"; \
		echo ""; \
		cat debian/changelog; \
	} > debian/changelog.new; \
	mv debian/changelog.new debian/changelog; \
	echo "Changelog updated manually without dch"

# Build Debian packages
build-packages: deb-changelog
	@echo "Running build_packages.sh to build Debian packages with version $(VERSION)"
	@./build_packages.sh

# Clean up
clean:
	rm -f $(gorgona_OBJ) $(gorgonaD_OBJ) $(TEST_OBJ) gorgona gorgonad $(TEST_EXEC)

# Rebuild everything
rebuild: clean all

# Phony targets
.PHONY: all clean rebuild deb-changelog build-packages test
